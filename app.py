import eventlet
eventlet.monkey_patch()

import os
import json
import csv
import uuid
import qrcode
import base64
import re
import smtplib
import threading
import queue
import mimetypes
import sys
import platform
import flask
import ipaddress
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory, make_response, jsonify, Response, abort, current_app
from functools import wraps
from werkzeug.utils import secure_filename
from io import BytesIO
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from how_it_works_data import get_step_data, get_all_step_data, get_step_navigation
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from video_manager import video_manager
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
from werkzeug.middleware.proxy_fix import ProxyFix
from bot_protection import bot_protector
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, Event, Form, Response, VolunteerAccess, VolunteerSession, Verification, ChatMessage
import logging
from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration
import tempfile

# ============================================================================
# DIRECTORY UTILITIES
# ============================================================================

def get_data_path(subpath=''):
    """Get absolute path to data directory"""
    base_dir = os.path.join(os.getcwd(), 'data')
    if subpath:
        return os.path.join(base_dir, subpath)
    return base_dir

# ============================================================================
# INITIALIZATION & CONFIGURATION
# ============================================================================

# Load environment variables
load_dotenv()

# Create directories before the app starts using them
os.makedirs(get_data_path('reports'), exist_ok=True)
os.makedirs(get_data_path('email_status'), exist_ok=True)
os.makedirs('static/uploads', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs(get_data_path('volunteers'), exist_ok=True)
os.makedirs(get_data_path('notifications'), exist_ok=True)

# Define Form Class
class CreateEventForm(FlaskForm):
    event_name = StringField(validators=[DataRequired()])
    description = TextAreaField(validators=[DataRequired()])

# Initialize Flask App
app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1
)
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventflow.db'  # or your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
# Email configuration - USING ENVIRONMENT VARIABLES
# Email configuration - USING RESEND API
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'eventflow.app2026@gmail.com')
MAIL_FROM = os.environ.get('MAIL_DEFAULT_SENDER', 'EventFlow <eventflow.app2026@gmail.com>')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY')

# Keep these for backward compatibility but they won't be used for SMTP
MAIL_PASSWORD = None  # Not needed for Resend
MAIL_SERVER = None    # Not needed for Resend  
MAIL_PORT = None      # Not needed for Resend

logging.basicConfig(level=logging.DEBUG)

# Email status tracking
email_status_queue = queue.Queue()
email_statuses = {}  # Store email status by user/session

print("="*80)
print("📧 EventFlow Email System - DEBUG VERSION")
print("="*80)
print(f"   Username: {MAIL_USERNAME}")
print(f"   Password length: {len(MAIL_PASSWORD) if MAIL_PASSWORD else 'NONE'}")
print(f"   Server: {MAIL_SERVER}:{MAIL_PORT}")
print("="*80)
print("🔧 Test and Real emails use IDENTICAL configuration")
print("="*80)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 
    'txt', 'csv', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar'
}

# Ensure required directories exist
os.makedirs(get_data_path('reports'), exist_ok=True)
os.makedirs(get_data_path('email_status'), exist_ok=True)
os.makedirs('static/uploads', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs(get_data_path('volunteers'), exist_ok=True)
os.makedirs(get_data_path('notifications'), exist_ok=True)

scheduler = BackgroundScheduler()

@app.before_request
def check_blocked_user():
    """Check if current user is blocked on every request."""
    # Skip for public endpoints
    exempt_endpoints = ['login', 'signup', 'verify_email', 'resend_otp', 
                       'logout', 'static', 'index', 'show_form', 
                       'submit_form', 'ip_debug', 'test_form_submission',
                       'account_blocked', 'account_blocked']
    
    if request.endpoint in exempt_endpoints:
        return
    
    if 'user_id' in session:
        user_id = session.get('user_id')
        users = load_users()
        
        if user_id in users and users[user_id].get('blocked', False):
            # Redirect to blocked account page instead of clearing session
            return redirect(url_for('account_blocked'))


@app.after_request
def add_ngrok_header(response):
    """Bypass the ngrok browser warning for all responses"""
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response

def admin_required(f):
    """Decorator to check if user is admin AND not blocked."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        user_id = session.get('user_id')
        users = load_users()
        
        # Check if user exists in database
        if user_id not in users:
            flash('User not found. Please log in again.', 'error')
            session.clear()
            return redirect(url_for('login'))
        
        user_data = users[user_id]
        
        # Check if user is blocked
        if user_data.get('blocked', False):
            # Show the blocked account page instead of redirecting to login
            reason = user_data.get('blocked_reason', 'Violation of terms of service')
            blocked_at = user_data.get('blocked_at', '')
            
            # Calculate block duration
            block_until = 'permanent'
            if blocked_at:
                try:
                    blocked_date = datetime.fromisoformat(blocked_at)
                    block_duration = 7
                    unblock_date = blocked_date + timedelta(days=block_duration)
                    if datetime.now() < unblock_date:
                        block_until = unblock_date.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            support_email = os.environ.get('SUPPORT_EMAIL', MAIL_USERNAME)
            
            return render_template('account_blocked.html',
                                 reason=reason,
                                 blocked_at=blocked_at,
                                 block_until=block_until,
                                 support_email=support_email)
        
        # TEMPORARY: Allow all logged-in users to access admin area
        # TODO: Implement proper admin check later
        print(f"Admin access granted to: {user_id}")
        return f(*args, **kwargs)
    
    return decorated_function

def login_required(f):
    """Decorator to check if user is logged in AND not blocked."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        
        user_id = session.get('user_id')
        users = load_users()
        
        # Check if user exists in database
        if user_id not in users:
            flash('User not found. Please log in again.', 'error')
            session.clear()
            return redirect(url_for('login'))
        
        user_data = users[user_id]
        
        # Check if user is blocked
        if user_data.get('blocked', False):
            # Show the blocked account page instead of redirecting to login
            reason = user_data.get('blocked_reason', 'Violation of terms of service')
            blocked_at = user_data.get('blocked_at', '')
            
            # Calculate block duration
            block_until = 'permanent'  # Default to permanent unless specified
            if blocked_at:
                try:
                    blocked_date = datetime.fromisoformat(blocked_at)
                    block_duration = 7  # Default 7 days
                    unblock_date = blocked_date + timedelta(days=block_duration)
                    if datetime.now() < unblock_date:
                        block_until = unblock_date.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            support_email = os.environ.get('SUPPORT_EMAIL', MAIL_USERNAME)
            
            return render_template('account_blocked.html',
                                 reason=reason,
                                 blocked_at=blocked_at,
                                 block_until=block_until,
                                 support_email=support_email)
        
        return f(*args, **kwargs)
    return decorated_function   

def get_real_ip():
    """Extract IPv4 address from request - ONLY returns IPv4"""
    import re
    import hashlib
    
    def is_valid_ipv4(ip):
        """Check if string is a valid IPv4 address"""
        if not ip or not isinstance(ip, str):
            return False
        
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if not match:
            return False
        
        # Check each octet is between 0-255
        for octet in match.groups():
            if not octet.isdigit():
                return False
            if int(octet) > 255:
                return False
        
        return True

    def extract_ipv4_from_string(ip_string):
        """Helper to extract IPv4 from potential proxy strings"""
        if not ip_string:
            return None
        
        # Split by comma for multiple IPs (common in X-Forwarded-For)
        ips = [ip.strip() for ip in ip_string.split(',')]
        
        for ip in ips:
            # Check if it's IPv4
            if is_valid_ipv4(ip):
                return ip
            
            # Handle IPv6-mapped IPv4 (e.g., ::ffff:192.168.1.1)
            if ip.startswith('::ffff:'):
                ipv4_part = ip[7:]  # Remove '::ffff:'
                if is_valid_ipv4(ipv4_part):
                    return ipv4_part
        
        return None

    # Common headers to check for IP addresses
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',  # Cloudflare
        'True-Client-IP',    # Akamai/Cloudflare
        'X-Client-IP'
    ]
    
    # Check all headers for IPv4
    for header in headers_to_check:
        header_value = request.headers.get(header)
        if header_value:
            ipv4 = extract_ipv4_from_string(header_value)
            if ipv4:
                return ipv4

    # Check remote_addr as a fallback
    remote_addr = request.remote_addr
    if remote_addr:
        ipv4 = extract_ipv4_from_string(remote_addr)
        if ipv4:
            return ipv4

    # If we get IPv6, convert it to a consistent pseudo-IPv4 for display purposes
    ipv6_address = None

    # Get IPv6 from headers if no IPv4 was found
    for header in headers_to_check:
        header_value = request.headers.get(header)
        if header_value and ':' in header_value and '.' not in header_value:
            ipv6_address = header_value.split(',')[0].strip()
            break

    if not ipv6_address and remote_addr and ':' in remote_addr:
        ipv6_address = remote_addr

    # Convert IPv6 to pseudo-IPv4 for consistent display
    if ipv6_address:
        # Create deterministic pseudo-IPv4 from IPv6 hash
        hash_obj = hashlib.md5(ipv6_address.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Convert to 192.x.x.x format (private range)
        part1 = str((int(hash_hex[0:2], 16) % 64) + 192)  # 192-255
        part2 = str(int(hash_hex[2:4], 16) % 256)
        part3 = str(int(hash_hex[4:6], 16) % 256)
        part4 = str(int(hash_hex[6:8], 16) % 256)
        
        pseudo_ip = f"{part1}.{part2}.{part3}.{part4}"
        print(f"Converted IPv6 {ipv6_address[:20]}... to pseudo-IPv4: {pseudo_ip}")
        return pseudo_ip

    return '0.0.0.0'

def init_directories():
    """Initialize all required directories"""
    # Data directories (persistent)
    data_dirs = ['email_status', 'volunteers', 'notifications', 'events', 'reports']
    for dir_name in data_dirs:
        os.makedirs(get_data_path(dir_name), exist_ok=True)
    
    # Static directories (non-persistent)
    static_dirs = ['static/uploads', 'static/qr_codes', 'logs']
    for dir_name in static_dirs:
        os.makedirs(dir_name, exist_ok=True)
    
    print("✅ Directories initialized")

# Call it in your app
init_directories()
    
def calculate_growth_stats():
    """Calculate month-over-month growth statistics"""
    # This is a simplified version - in production, you'd track monthly stats
    
    stats = get_server_statistics()
    
    # For now, return placeholder growth percentages
    return {
        'user_growth': 5,  # 5% growth this month
        'event_growth': 12,  # 12% growth this month
        'form_growth': 8,  # 8% growth this month
        'submission_growth': 15,  # 15% growth this month
        'total_users': stats['users'],
        'total_events': stats['events'],
        'total_forms': stats['forms'],
        'total_submissions': stats['registrations']
    }    

def init_volunteer_directories():
    """Initialize directories for volunteer system"""
    directories = [
        'data/verifications',
        'data/volunteers'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✅ Volunteer directories initialized")
    
def check_form_blocked_enhanced(form_id):
    """Check if form is blocked - returns tuple (is_blocked, reason, timestamp, blocked_data)"""
    blocked_forms = load_blocked_forms()
    form_info = blocked_forms.get(form_id)
    
    if form_info:
        # Check if block is still valid (default 7 days)
        blocked_time = datetime.fromisoformat(form_info.get('blocked_at', datetime.now().isoformat()))
        block_duration = form_info.get('block_duration', 7)  # days
        
        # Calculate if block has expired
        if (datetime.now() - blocked_time).days >= block_duration:
            # Unblock the form
            blocked_forms.pop(form_id)
            save_blocked_forms(blocked_forms)
            log_message(f"Form {form_id} automatically unblocked after {block_duration} days", "MODERATION")
            return False, None, None, None
        
        return True, form_info.get('reason'), form_info.get('blocked_at'), form_info
    
    return False, None, None, None
    
def show_blocked_form_page(form_id, block_reason, block_timestamp):
    """Show blocked form page for non-admin users"""
    # Get form and event info for blocked page
    form_found = False
    event_found = None
    form_data = None
    creator_info = {}
    
    # Search for the form to get info for blocked page
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                    event = json.load(f)
                
                for form in event.get('forms', []):
                    if form['id'] == form_id:
                        form_found = True
                        event_found = event
                        form_data = form
                        
                        # Get creator information
                        creator_id = event.get('creator_id')
                        if creator_id:
                            users = load_users()
                            creator_data = users.get(creator_id)
                            
                            if creator_data:
                                creator_info = {
                                    'user_id': creator_id,
                                    'name': creator_data.get('username', 'Unknown User'),
                                    'email': creator_data.get('email', ''),
                                    'verified': creator_data.get('email_verified', False),
                                    'join_date': creator_data.get('created_at', ''),
                                    'events_created': 0
                                }
                                
                                # Count events created by this user
                                for ev_file in os.listdir('data/events'):
                                    if ev_file.endswith('.json'):
                                        try:
                                            with open(f'data/events/{ev_file}', 'r') as f:
                                                ev = json.load(f)
                                                if ev.get('creator_id') == creator_id:
                                                    creator_info['events_created'] += 1
                                        except:
                                            continue
                        break
                
                if form_found:
                    break
                    
            except Exception as e:
                continue
    
    # Show blocked form page using separate template
    return render_template('form_blocked.html',
                         form_id=form_id,
                         block_reason=block_reason,
                         block_timestamp=block_timestamp,
                         form=form_data,  # Pass form data if found
                         event=event_found,  # Pass event data if found
                         creator_info=creator_info)

def block_user_account(user_id, reason, duration_days, blocked_by):
    """Block a user account"""
    users = load_users()
    
    if user_id in users:
        users[user_id]['blocked'] = True
        users[user_id]['blocked_reason'] = reason
        users[user_id]['blocked_at'] = datetime.now().isoformat()
        users[user_id]['blocked_by'] = blocked_by
        users[user_id]['block_duration'] = duration_days
        
        save_users(users)
        
        # Send notification email
        user_email = users[user_id].get('email')
        username = users[user_id].get('username')
        if user_email:
            send_account_blocked_email(user_email, username, reason, duration_days, blocked_by)
        
        return True
    return False
    
def migrate_csv_to_include_attendee_ip(event_id, form_id):
    """Add Attendee IP column to existing CSV files"""
    try:
        csv_path = get_data_path(f'events/{event_id}/{form_id}.csv')  # CHANGED
        if not os.path.exists(csv_path):
            return False
        
        # Read existing CSV
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        if not rows:
            return False
        
        headers = rows[0]
        
        # Check if Attendee IP already exists
        if 'Attendee IP' in headers:
            return True  # Already migrated
        
        # Add Attendee IP header
        headers.insert(2, 'Attendee IP')
        
        # Add 'N/A' for existing responses (since we don't have historical IPs)
        for i in range(1, len(rows)):
            if len(rows[i]) >= 2:
                rows[i].insert(2, 'N/A')  # N/A for historical data
            else:
                # Handle malformed rows
                while len(rows[i]) < 2:
                    rows[i].append('N/A')
                rows[i].insert(2, 'N/A')
        
        # Write back
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(rows)
        
        log_message(f"✅ Migrated CSV for {event_id}/{form_id} to include Attendee IP", "MIGRATION")
        return True
        
    except Exception as e:
        log_message(f"❌ Error migrating CSV: {e}", "ERROR")
        return False 

    
def get_file_type_categories():
    """Get categorized file types for file upload questions"""
    return {
        'images': {
            'name': 'Images',
            'extensions': {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'tiff'},
            'icon': 'bi-image',
            'mime_types': {'image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/svg+xml', 'image/webp', 'image/tiff'}
        },
        'pdf': {
            'name': 'PDF Documents',
            'extensions': {'pdf'},
            'icon': 'bi-file-pdf',
            'mime_types': {'application/pdf'}
        },
        'documents': {
            'name': 'Documents',
            'extensions': {'doc', 'docx', 'txt', 'rtf', 'odt', 'pages'},
            'icon': 'bi-file-text',
            'mime_types': {'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/rtf', 'application/vnd.oasis.opendocument.text'}
        },
        'spreadsheets': {
            'name': 'Spreadsheets',
            'extensions': {'xls', 'xlsx', 'csv', 'ods', 'numbers'},
            'icon': 'bi-file-spreadsheet',
            'mime_types': {'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/csv', 'application/vnd.oasis.opendocument.spreadsheet'}
        },
        'presentations': {
            'name': 'Presentations',
            'extensions': {'ppt', 'pptx', 'odp', 'key'},
            'icon': 'bi-file-slides',
            'mime_types': {'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.oasis.opendocument.presentation'}
        },
        'archives': {
            'name': 'Archives',
            'extensions': {'zip', 'rar', '7z', 'tar', 'gz'},
            'icon': 'bi-file-zip',
            'mime_types': {'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/x-tar', 'application/gzip'}
        },
        'audio': {
            'name': 'Audio Files',
            'extensions': {'mp3', 'wav', 'ogg', 'm4a', 'flac', 'aac'},
            'icon': 'bi-file-music',
            'mime_types': {'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4', 'audio/flac', 'audio/aac'}
        },
        'video': {
            'name': 'Video Files',
            'extensions': {'mp4', 'mov', 'avi', 'mkv', 'webm', 'wmv', 'flv'},
            'icon': 'bi-file-play',
            'mime_types': {'video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/x-matroska', 'video/webm', 'video/x-ms-wmv', 'video/x-flv'}
        },
        'code': {
            'name': 'Code Files',
            'extensions': {'py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'php', 'json', 'xml'},
            'icon': 'bi-file-code',
            'mime_types': {'text/x-python', 'application/javascript', 'text/html', 'text/css', 'text/x-java-source', 'text/x-c++src', 'text/x-c', 'application/x-httpd-php', 'application/json', 'application/xml'}
        }
    }
    
@app.template_filter()
def fromisoformat(date_string):
    """Convert ISO format string to datetime object"""
    if not date_string:
        return None
    try:
        date_string = date_string.replace('T', ' ') if 'T' in date_string else date_string
        return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
    except Exception:
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d', '%d/%m/%Y %H:%M:%S'):
            try:
                return datetime.strptime(date_string, fmt)
            except ValueError:
                continue
        return None

@app.template_filter()
def clamp(value, min_val, max_val):
    """Clamp a value between min and max"""
    try:
        val = float(value)
        return max(min_val, min(val, max_val))
    except:
        return value

@app.context_processor
def inject_now():
    """Inject current datetime and utility functions into templates"""
    def is_form_active(form_data):
        """Check form status for template"""
        return check_form_active(form_data)
    
    def get_current_time():
        """Get current server time"""
        return datetime.now()
    
    return {
        'now': datetime.now(),
        'timedelta': timedelta,
        'current_time': get_current_time,
        'is_form_active': is_form_active
    }
    

# ============================================================================
# FORM REPORTING ROUTES
# ============================================================================

def debug_form_submission(request_form, question_index):
    """Debug helper for form submissions"""
    print(f"\n🔍 DEBUG FORM SUBMISSION for question {question_index}:")
    print("All form keys:")
    for key in request_form.keys():
        if str(question_index) in key or 'file' in key.lower():
            value = request_form.get(key)
            if value:
                print(f"  {key}: {value}")
            else:
                # Check if it's a list
                values = request_form.getlist(key)
                if values:
                    print(f"  {key} (list): {values}")

def load_form_reports():
    """Load form reports from JSON file"""
    try:
        os.makedirs('data/reports', exist_ok=True)
        reports_file = 'data/reports/form_reports.json'
        if os.path.exists(reports_file):
            with open(reports_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log_message(f"Error loading form reports: {e}", "ERROR")
    return {}

def save_form_reports(reports_data):
    """Save form reports to JSON file"""
    try:
        os.makedirs('data/reports', exist_ok=True)
        reports_file = 'data/reports/form_reports.json'
        with open(reports_file, 'w', encoding='utf-8') as f:
            json.dump(reports_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log_message(f"Error saving form reports: {e}", "ERROR")
        return False

def load_blocked_forms():
    """Load blocked forms data"""
    try:
        os.makedirs('data/reports', exist_ok=True)
        blocked_file = 'data/reports/blocked_forms.json'
        if os.path.exists(blocked_file):
            with open(blocked_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log_message(f"Error loading blocked forms: {e}", "ERROR")
    return {}

def save_blocked_forms(blocked_data):
    """Save blocked forms data"""
    try:
        os.makedirs('data/reports', exist_ok=True)
        blocked_file = 'data/reports/blocked_forms.json'
        with open(blocked_file, 'w', encoding='utf-8') as f:
            json.dump(blocked_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log_message(f"Error saving blocked forms: {e}", "ERROR")
        return False



def send_welcome_email_with_guidelines(email, username):
    """Send welcome email with comprehensive guidelines information"""
    try:
        subject = "🎉 Welcome to EventFlow - Let's Get Started!"
        dashboard_url = url_for('dashboard', _external=True)
        guidelines_url = url_for('user_guidelines', _external=True)
        login_url = url_for('login', _external=True)
        create_event_url = url_for('create_event', _external=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 0; background: #f8fafc; }}
                .container {{ max-width: 650px; margin: auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); color: white; padding: 40px 30px; text-align: center; }}
                .content {{ padding: 40px 30px; }}
                .section {{ margin: 30px 0; padding: 25px; border-radius: 12px; }}
                .guidelines-section {{ background: linear-gradient(to right, #e8f4fd, #f0efff); border-left: 5px solid #4361ee; }}
                .getting-started {{ background: #f1f5f9; border-left: 5px solid #10b981; }}
                .button {{ display: inline-block; background: #4361ee; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px 5px; }}
                .button-secondary {{ background: #6c757d; }}
                .button-success {{ background: #10b981; }}
                .feature-box {{ background: white; padding: 20px; border-radius: 10px; margin: 15px 0; box-shadow: 0 3px 10px rgba(0,0,0,0.05); border: 1px solid #e5e7eb; }}
                .feature-icon {{ color: #4361ee; font-size: 24px; margin-right: 15px; }}
                .footer {{ background: #1e293b; color: white; padding: 30px; text-align: center; }}
                .step {{ display: flex; align-items: center; margin: 20px 0; }}
                .step-number {{ background: #4361ee; color: white; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; margin-right: 15px; }}
                .tips-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; border-radius: 8px; margin: 25px 0; }}
                .emoji {{ font-size: 24px; margin-right: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Header -->
                <div class="header">
                    <h1 style="margin: 0; font-size: 32px;">🎉 Welcome to EventFlow!</h1>
                    <p style="font-size: 18px; opacity: 0.9; margin-top: 10px;">Hello {username}, we're excited to have you onboard!</p>
                </div>
                
                <!-- Main Content -->
                <div class="content">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <p style="font-size: 18px; color: #4b5563;">Your journey to seamless event management starts here. Complete your email verification to unlock all features.</p>
                    </div>
                    
                    <!-- Getting Started Section -->
                    <div class="section getting-started">
                        <h2 style="color: #10b981; margin-top: 0;">🚀 Getting Started</h2>
                        
                        <div class="step">
                            <div class="step-number">1</div>
                            <div>
                                <h3 style="margin: 0 0 5px 0;">Check Your Email</h3>
                                <p style="margin: 0; color: #6b7280;">Find the verification code we just sent to: <strong>{email}</strong></p>
                            </div>
                        </div>
                        
                        <div class="step">
                            <div class="step-number">2</div>
                            <div>
                                <h3 style="margin: 0 0 5px 0;">Enter Verification Code</h3>
                                <p style="margin: 0; color: #6b7280;">Return to EventFlow and enter the 6-digit code from this email</p>
                            </div>
                        </div>
                        
                        <div class="step">
                            <div class="step-number">3</div>
                            <div>
                                <h3 style="margin: 0 0 5px 0;">Start Creating!</h3>
                                <p style="margin: 0; color: #6b7280;">Once verified, you can create your first event immediately</p>
                            </div>
                        </div>
                        
                        <div style="text-align: center; margin-top: 30px;">
                            <a href="{login_url}" class="button">
                                <span class="emoji">🔐</span> Complete Verification
                            </a>
                        </div>
                    </div>
                    
                    <!-- Quick Feature Overview -->
                    <div style="margin: 40px 0;">
                        <h2 style="color: #4361ee; text-align: center;">✨ What You Can Do</h2>
                        <div class="feature-box">
                            <div style="display: flex; align-items: center;">
                                <span class="feature-icon">📅</span>
                                <div>
                                    <h4 style="margin: 0 0 10px 0;">Create & Manage Events</h4>
                                    <p style="margin: 0; color: #6b7280;">Organize any type of event - conferences, workshops, meetups, and more</p>
                                </div>
                            </div>
                        </div>
                        
                        <div class="feature-box">
                            <div style="display: flex; align-items: center;">
                                <span class="feature-icon">📝</span>
                                <div>
                                    <h4 style="margin: 0 0 10px 0;">Build Registration Forms</h4>
                                    <p style="margin: 0; color: #6b7280;">Design custom forms with various question types and file uploads</p>
                                </div>
                            </div>
                        </div>
                        
                        <div class="feature-box">
                            <div style="display: flex; align-items: center;">
                                <span class="feature-icon">📊</span>
                                <div>
                                    <h4 style="margin: 0 0 10px 0;">Track & Analyze Responses</h4>
                                    <p style="margin: 0; color: #6b7280;">Monitor submissions in real-time with CSV export and analytics</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Guidelines Section -->
                    <div class="section guidelines-section">
                        <h2 style="color: #4361ee; margin-top: 0;">
                            <span class="emoji">📋</span> Our Commitment to Responsible Data Use
                        </h2>
                        
                        <p>At EventFlow, we believe in <strong>empowering organizers while protecting participants</strong>. Before you start creating events, please review our guidelines to ensure a safe and respectful experience for everyone.</p>
                        
                        <div class="tips-box">
                            <h4 style="margin-top: 0; color: #856404;">💡 Quick Guidelines Overview:</h4>
                            <ul style="margin-bottom: 0;">
                                <li><strong>Be transparent</strong> about data collection</li>
                                <li><strong>Only collect necessary information</strong> from participants</li>
                                <li><strong>Respect privacy</strong> - don't share data without consent</li>
                                <li><strong>Use appropriate content</strong> - no spam or harassment</li>
                                <li><strong>Report issues</strong> - help us maintain a safe community</li>
                            </ul>
                        </div>
                        
                        <div style="text-align: center; margin: 25px 0;">
                            <a href="{guidelines_url}" class="button" target="_blank">
                                <span class="emoji">📖</span> Read Full User Guidelines
                            </a>
                        </div>
                        
                        <p style="text-align: center; color: #6b7280; font-style: italic;">
                            "Great events start with great planning and respect for participant privacy."
                        </p>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div style="text-align: center; margin: 40px 0 20px 0;">
                        <p style="font-size: 18px; margin-bottom: 20px;">Ready to begin?</p>
                        <a href="{guidelines_url}" class="button-secondary" target="_blank">
                            Guidelines First
                        </a>
                        <a href="{create_event_url}" class="button-success">
                            Create First Event
                        </a>
                    </div>
                </div>
                
                <!-- Footer -->
                <div class="footer">
                    <h3 style="margin-top: 0; color: #f1f5f9;">EventFlow</h3>
                    <p style="opacity: 0.8; margin-bottom: 20px;">Simplifying event management with responsibility and care</p>
                    
                    <div style="border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px; margin-top: 20px;">
                        <p style="font-size: 14px; opacity: 0.7; margin: 5px 0;">
                            This is an automated welcome email. You're receiving this because you signed up for EventFlow.
                        </p>
                        <p style="font-size: 12px; opacity: 0.6; margin: 5px 0;">
                            © {datetime.now().year} EventFlow. All rights reserved.<br>
                            Building better events together.
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        success, message = send_email_simple(email, subject, html_content)
        
        if success:
            log_message(f"✅ Welcome email with guidelines sent to {email}", "SUCCESS")
            return True
        else:
            log_message(f"❌ Failed to send welcome email to {email}: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"❌ Welcome email exception: {e}", "ERROR")
        return False

def send_account_activated_email(email, username):
    """Send confirmation email after account activation"""
    try:
        subject = "✅ Account Activated - Welcome to EventFlow!"
        dashboard_url = url_for('dashboard', _external=True)
        guidelines_url = url_for('user_guidelines', _external=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: auto; background: #f8fafc; padding: 0;">
                <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 40px; text-align: center;">
                    <h1 style="margin: 0; font-size: 28px;">✅ Account Activated!</h1>
                    <p style="font-size: 18px; opacity: 0.9; margin-top: 10px;">Hi {username}, you're all set to use EventFlow</p>
                </div>
                
                <div style="padding: 40px;">
                    <div style="background: white; padding: 25px; border-radius: 10px; box-shadow: 0 3px 15px rgba(0,0,0,0.05); margin-bottom: 25px;">
                        <h2 style="color: #10b981; margin-top: 0;">🎉 You're In!</h2>
                        <p>Your email has been verified and your EventFlow account is now fully activated. You can access all features immediately.</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{dashboard_url}" style="background: #10b981; color: white; padding: 14px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                                Go to Dashboard
                            </a>
                        </div>
                    </div>
                    
                    <div style="background: #e8f4fd; padding: 25px; border-radius: 10px; border-left: 4px solid #4361ee; margin: 25px 0;">
                        <h3 style="color: #4361ee; margin-top: 0;">📋 Quick Reminder</h3>
                        <p>As a new EventFlow organizer, remember to:</p>
                        <ul>
                            <li>Review our <a href="{guidelines_url}" style="color: #4361ee; font-weight: bold;">User Guidelines</a> for best practices</li>
                            <li>Collect only necessary participant data</li>
                            <li>Be transparent about how data will be used</li>
                            <li>Use form scheduling features effectively</li>
                        </ul>
                    </div>
                    
                    <div style="background: #f1f5f9; padding: 20px; border-radius: 8px; text-align: center; margin-top: 30px;">
                        <p style="margin: 0; color: #6b7280; font-size: 14px;">
                            Need help getting started? Check out the tutorials in your dashboard or contact our support team.
                        </p>
                    </div>
                </div>
                
                <div style="background: #1e293b; color: white; padding: 25px; text-align: center;">
                    <p style="margin: 0; opacity: 0.8; font-size: 14px;">
                        EventFlow Team • {datetime.now().strftime('%B %d, %Y')}<br>
                        © {datetime.now().year} EventFlow. Building better events together.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        success, message = send_email_simple(email, subject, html_content)
        
        if success:
            log_message(f"✅ Account activation email sent to {email}", "SUCCESS")
            return True
        else:
            log_message(f"❌ Failed to send activation email: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"❌ Activation email exception: {e}", "ERROR")
        return False


def calculate_account_age(created_at):
    """Calculate how long the account has existed"""
    if not created_at:
        return "New"
    
    try:
        join_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
        days_old = (datetime.now() - join_date).days
        
        if days_old == 0:
            return "Today"
        elif days_old == 1:
            return "1 day"
        elif days_old < 7:
            return f"{days_old} days"
        elif days_old < 30:
            weeks = days_old // 7
            return f"{weeks} week{'s' if weeks > 1 else ''}"
        elif days_old < 365:
            months = days_old // 30
            return f"{months} month{'s' if months > 1 else ''}"
        else:
            years = days_old // 365
            return f"{years} year{'s' if years > 1 else ''}"
    except:
        return "Unknown"

def calculate_user_storage(user_id):
    """Calculate storage used by user (simplified)"""
    try:
        total_size = 0
        
        # Calculate size of event files
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r') as f:
                        event = json.load(f)
                        if event.get('creator_id') == user_id:
                            # Add event file size
                            event_file_path = f'data/events/{filename}'
                            if os.path.exists(event_file_path):
                                total_size += os.path.getsize(event_file_path)
                            
                            # Add CSV file sizes
                            event_id = event.get('id')
                            for form in event.get('forms', []):
                                csv_path = get_data_path(f'events/{event_id}/{form["id"]}.csv')  # CHANGED
                                if os.path.exists(csv_path):
                                    total_size += os.path.getsize(csv_path)
                                
                                # Add uploaded files size
                                upload_dir = f'static/uploads/events/{event_id}/{form["id"]}'
                                if os.path.exists(upload_dir):
                                    for file in os.listdir(upload_dir):
                                        file_path = os.path.join(upload_dir, file)
                                        if os.path.isfile(file_path):
                                            total_size += os.path.getsize(file_path)
                except:
                    continue
        
        # Convert to MB
        size_mb = total_size / (1024 * 1024)
        
        if size_mb < 1:
            return f"{size_mb * 1024:.1f} KB"
        elif size_mb < 1024:
            return f"{size_mb:.1f} MB"
        else:
            return f"{size_mb / 1024:.1f} GB"
            
    except Exception as e:
        log_message(f"Error calculating user storage: {e}", "ERROR")
        return "Unknown"

# In your load_users() function, ensure blocked status is included
def load_users():
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
            
            # Ensure all users have blocked status field
            for user_id, user_data in users.items():
                if 'blocked' not in user_data:
                    user_data['blocked'] = False
                if 'blocked_reason' not in user_data:
                    user_data['blocked_reason'] = ''
                if 'blocked_at' not in user_data:
                    user_data['blocked_at'] = ''
                if 'blocked_by' not in user_data:
                    user_data['blocked_by'] = ''
                    
        return users
    except:
        return {}

# In save_users(), it will automatically save the blocked fields

def send_report_notification(form_id, form_title, event_name, creator_id, report_reason, reporter_email, reporter_name, report_details):
    """Send email notification to admin about form report"""
    try:
        # Load admin email settings
        settings_file = 'data/feedback_settings.json'
        admin_email = None
        
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
                admin_email = settings.get('admin_email', os.environ.get('ADMIN_EMAIL', MAIL_USERNAME))
        else:
            admin_email = os.environ.get('ADMIN_EMAIL', MAIL_USERNAME)
        
        if not admin_email:
            log_message("No admin email configured for report notifications", "ERROR")
            return False
        
        subject = f"🚨 FORM REPORTED: {form_title}"
        
        # Get reason display text
        reason_display = {
            'inappropriate_content': 'Inappropriate Content',
            'spam_scam': 'Spam or Scam',
            'privacy_violation': 'Privacy Violation',
            'copyright_infringement': 'Copyright Infringement',
            'impersonation': 'Impersonation',
            'harassment': 'Harassment or Bullying',
            'other': 'Other Issue'
        }.get(report_reason, 'Unknown Reason')
        
        # Get creator info
        creator_info = {}
        users = load_users()
        if creator_id in users:
            creator_info = users[creator_id]
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 800px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .report-info {{ background: #fee2e2; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .form-info {{ background: #e8f4fd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .creator-info {{ background: #f0efff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .action-buttons {{ margin: 25px 0; }}
                .btn {{ display: inline-block; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 5px; }}
                .btn-danger {{ background: #dc3545; color: white; }}
                .btn-warning {{ background: #ffc107; color: #000; }}
                .btn-info {{ background: #0dcaf0; color: white; }}
                .btn-success {{ background: #198754; color: white; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .priority-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; background: #dc3545; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 FORM REPORTED</h1>
                    <p>Urgent attention required</p>
                    <span class="priority-badge">HIGH PRIORITY</span>
                </div>
                <div class="content">
                    <div class="report-info">
                        <h3>📋 Report Details</h3>
                        <p><strong>Reason:</strong> {reason_display}</p>
                        <p><strong>Reported By:</strong> {reporter_name or 'Anonymous'}{f' ({reporter_email})' if reporter_email else ''}</p>
                        <p><strong>Report Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Report ID:</strong> {str(uuid.uuid4())[:8].upper()}</p>
                        {f'<p><strong>Additional Details:</strong><br>{report_details[:500]}</p>' if report_details else ''}
                    </div>
                    
                    <div class="form-info">
                        <h3>📝 Form Information</h3>
                        <p><strong>Form Title:</strong> {form_title}</p>
                        <p><strong>Event:</strong> {event_name}</p>
                        <p><strong>Form ID:</strong> {form_id}</p>
                        <p><strong>Report Count:</strong> 1 new report (check reports database for total)</p>
                    </div>
                    
                    <div class="creator-info">
                        <h3>👤 Creator Information</h3>
                        <p><strong>Creator ID:</strong> {creator_id}</p>
                        <p><strong>Name:</strong> {creator_info.get('username', 'Unknown')}</p>
                        <p><strong>Email:</strong> {creator_info.get('email', 'Unknown')}</p>
                        <p><strong>Account Created:</strong> {creator_info.get('created_at', 'Unknown')[:10]}</p>
                        <p><strong>Email Verified:</strong> {'✅ Yes' if creator_info.get('email_verified') else '❌ No'}</p>
                    </div>
                    
                    <div class="action-buttons">
                        <p><strong>Quick Actions:</strong></p>
                        <a href="{url_for('admin_form_reports', _external=True)}" class="btn btn-danger">
                            <i class="bi bi-shield-exclamation"></i> View All Reports
                        </a>
                        <a href="{url_for('show_form', form_id=form_id, _external=True)}" class="btn btn-warning">
                            <i class="bi bi-eye"></i> View Form
                        </a>
                        <a href="{url_for('admin_debug_form', form_id=form_id, _external=True)}" class="btn btn-info">
                            <i class="bi bi-bug"></i> Debug Form
                        </a>
                        <a href="mailto:{creator_info.get('email', '')}?subject=Regarding Your Reported Form: {form_title}" class="btn btn-success">
                            <i class="bi bi-envelope"></i> Contact Creator
                        </a>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <p><strong>📈 Next Steps:</strong></p>
                        <ol>
                            <li>Review the reported form content</li>
                            <li>Check form creator's history and reputation</li>
                            <li>Decide whether to temporarily block the form</li>
                            <li>Investigate reports database for similar patterns</li>
                            <li>Notify creator if form violates terms of service</li>
                        </ol>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated notification from EventFlow Moderation System.</p>
                        <p>Report ID: {str(uuid.uuid4())[:16]} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email
        success, message = send_email_simple(admin_email, subject, html_content)
        
        if success:
            log_message(f"Report notification sent to admin for form {form_id}", "INFO")
            return True
        else:
            log_message(f"Failed to send report notification: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"Error sending report notification: {e}", "ERROR")
        return False


def init_volunteer_system():
    """Initialize volunteer system directories"""
    directories = [
        'data/verifications',
        'data/volunteers',
        'static/qr_codes'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✅ Volunteer system initialized")


def send_account_blocked_email(user_email, username, reason, duration_days, blocked_by):
    """Send email notification when account is blocked"""
    try:
        subject = "⚠️ Your EventFlow Account Has Been Temporarily Blocked"
        
        duration_text = "permanently" if duration_days == 0 else f"for {duration_days} day{'s' if duration_days > 1 else ''}"
        support_email = os.environ.get('SUPPORT_EMAIL', MAIL_USERNAME)
        guidelines_url = url_for('user_guidelines', _external=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .warning-box {{ background: #fee2e2; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc3545; }}
                .info-box {{ background: #e8f4fd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .action-buttons {{ margin: 25px 0; }}
                .btn {{ display: inline-block; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 5px; }}
                .btn-primary {{ background: #4361ee; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ Account Access Restricted</h1>
                    <p>Temporary account suspension</p>
                </div>
                <div class="content">
                    <p>Hello {username},</p>
                    
                    <div class="warning-box">
                        <h3>Account Status: <span style="color: #dc3545;">BLOCKED</span></h3>
                        <p><strong>Duration:</strong> {duration_text}</p>
                        <p><strong>Effective:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Blocked By:</strong> EventFlow Administration Team</p>
                    </div>
                    
                    <div class="info-box">
                        <h4>📋 Reason for Block</h4>
                        <p><strong>{reason}</strong></p>
                        
                        <h4 style="margin-top: 20px;">🚫 Restricted Features</h4>
                        <ul>
                            <li>Creating new events or forms</li>
                            <li>Accessing form responses</li>
                            <li>Sending form invitations</li>
                            <li>Modifying existing forms</li>
                        </ul>
                        
                        <h4 style="margin-top: 20px;">✅ What You Can Still Do</h4>
                        <ul>
                            <li>View existing events (read-only)</li>
                            <li>Download your existing data</li>
                            <li>Contact support for assistance</li>
                            <li>Review our User Guidelines</li>
                        </ul>
                    </div>
                    
                    <div class="action-buttons">
                        <p><strong>Next Steps:</strong></p>
                        <a href="mailto:{support_email}?subject=Account Block Inquiry: {username}" class="btn btn-primary">
                            <i class="bi bi-envelope"></i> Contact Support
                        </a>
                        <a href="{guidelines_url}" class="btn btn-secondary">
                            <i class="bi bi-journal-text"></i> Review Guidelines
                        </a>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <p><strong>📝 Appeal Process:</strong></p>
                        <ol>
                            <li>Review the reason for blocking above</li>
                            <li>Contact our support team with any questions</li>
                            <li>If this was a mistake, provide evidence to support your appeal</li>
                            <li>Once resolved, your account will be restored automatically or manually</li>
                        </ol>
                    </div>
                    
                    <p>We take community safety and platform integrity seriously. This action was taken to ensure a positive experience for all EventFlow users.</p>
                    
                    <div class="footer">
                        <p>This is an automated notification from EventFlow Account Security System.</p>
                        <p>Reference ID: ACC-BLOCK-{str(uuid.uuid4())[:8].upper()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        success, message = send_email_simple(user_email, subject, html_content)
        
        if success:
            log_message(f"Account blocked notification sent to {user_email}", "NOTIFICATION")
            return True
        else:
            log_message(f"Failed to send block notification: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"Error sending block notification email: {e}", "ERROR")
        return False

def send_account_unblocked_email(user_email, username, reason, unblocked_by):
    """Send email notification when account is unblocked"""
    try:
        subject = "✅ Your EventFlow Account Has Been Restored"
        
        support_email = os.environ.get('SUPPORT_EMAIL', MAIL_USERNAME)
        dashboard_url = url_for('dashboard', _external=True)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #198754 0%, #146c43 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .success-box {{ background: #d1fae5; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #198754; }}
                .info-box {{ background: #e8f4fd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .btn {{ display: inline-block; background: #198754; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Account Restored</h1>
                    <p>Welcome back to EventFlow!</p>
                </div>
                <div class="content">
                    <p>Hello {username},</p>
                    
                    <div class="success-box">
                        <h3>Account Status: <span style="color: #198754;">ACTIVE</span></h3>
                        <p><strong>Restored At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Restored By:</strong> EventFlow Administration Team</p>
                        <p><strong>Reason:</strong> {reason}</p>
                    </div>
                    
                    <p>Your EventFlow account access has been fully restored. You can now use all platform features as normal.</p>
                    
                    <div class="info-box">
                        <h4>🎉 What's Now Available</h4>
                        <ul>
                            <li>Create new events and forms</li>
                            <li>Access and manage all your existing data</li>
                            <li>Send form invitations and share links</li>
                            <li>Export data and generate reports</li>
                            <li>All other EventFlow features</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{dashboard_url}" class="btn">
                            <i class="bi bi-speedometer2"></i> Go to Dashboard
                        </a>
                    </div>
                    
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <p><strong>📋 Important Reminder:</strong></p>
                        <p>Please ensure your use of EventFlow complies with our User Guidelines to avoid future restrictions. We're committed to maintaining a safe and respectful platform for all users.</p>
                        
                        <p style="margin-top: 15px;">
                            <strong>Need help?</strong> Contact our support team: 
                            <a href="mailto:{support_email}" style="color: #4361ee;">{support_email}</a>
                        </p>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated notification from EventFlow Account Security System.</p>
                        <p>Reference ID: ACC-RESTORE-{str(uuid.uuid4())[:8].upper()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        success, message = send_email_simple(user_email, subject, html_content)
        
        if success:
            log_message(f"Account unblocked notification sent to {user_email}", "NOTIFICATION")
            return True
        else:
            log_message(f"Failed to send unblock notification: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"Error sending unblock notification email: {e}", "ERROR")
        return False


def check_form_blocked(form_id):
    """Check if form is blocked"""
    blocked_forms = load_blocked_forms()
    form_info = blocked_forms.get(form_id)
    
    if form_info:
        # Check if block is still valid (default 7 days)
        blocked_time = datetime.fromisoformat(form_info.get('blocked_at', datetime.now().isoformat()))
        block_duration = form_info.get('block_duration', 7)  # days
        
        # Calculate if block has expired
        if (datetime.now() - blocked_time).days >= block_duration:
            # Unblock the form
            blocked_forms.pop(form_id)
            save_blocked_forms(blocked_forms)
            log_message(f"Form {form_id} automatically unblocked after {block_duration} days", "INFO")
            return False, None, None
        
        return True, form_info.get('reason'), form_info.get('blocked_at')
    
    return False, None, None

@app.route('/report_form', methods=['POST'])
def report_form():
    """Handle form reporting"""
    try:
        # Get form data
        form_id = request.form.get('form_id')
        event_id = request.form.get('event_id')
        form_title = request.form.get('form_title')
        creator_id = request.form.get('creator_id')
        report_reason = request.form.get('report_reason')
        report_details = request.form.get('report_details', '').strip()[:500]
        reporter_email = request.form.get('reporter_email', '').strip()
        reporter_name = request.form.get('reporter_name', 'Anonymous')
        reporter_id = request.form.get('reporter_id')
        
        # Validate required fields
        if not all([form_id, event_id, form_title, report_reason]):
            return jsonify({'success': False, 'error': 'Missing required information'})
        
        # Load existing reports
        reports = load_form_reports()
        
        # Initialize form reports if not exists
        if form_id not in reports:
            reports[form_id] = {
                'form_title': form_title,
                'event_id': event_id,
                'creator_id': creator_id,
                'total_reports': 0,
                'reporters': [],
                'reports_by_reason': {},
                'first_reported': datetime.now().isoformat(),
                'last_reported': datetime.now().isoformat()
            }
        
        # Check if this reporter already reported this form
        existing_report = False
        for reporter in reports[form_id]['reporters']:
            if reporter.get('reporter_id') == reporter_id or reporter.get('reporter_email') == reporter_email:
                existing_report = True
                break
        
        if existing_report:
            return jsonify({
                'success': False, 
                'error': 'You have already reported this form. Our team will review it shortly.'
            })
        
        # Add report
        report_data = {
            'id': str(uuid.uuid4()),
            'reporter_id': reporter_id,
            'reporter_name': reporter_name,
            'reporter_email': reporter_email,
            'reason': report_reason,
            'details': report_details,
            'timestamp': datetime.now().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string[:200]
        }
        
        reports[form_id]['reporters'].append(report_data)
        reports[form_id]['total_reports'] += 1
        reports[form_id]['last_reported'] = datetime.now().isoformat()
        
        # Update reports by reason count
        if report_reason not in reports[form_id]['reports_by_reason']:
            reports[form_id]['reports_by_reason'][report_reason] = 0
        reports[form_id]['reports_by_reason'][report_reason] += 1
        
        # Save reports
        save_form_reports(reports)
        
        # Send notification to admin
        notification_sent = send_report_notification(
            form_id, form_title, '', creator_id, report_reason,
            reporter_email, reporter_name, report_details
        )
        
        # Check if form should be blocked (e.g., after 3 reports)
        should_block = False
        if reports[form_id]['total_reports'] >= 3:
            # Block the form
            blocked_forms = load_blocked_forms()
            
            # Get reason display text
            reason_display = {
                'inappropriate_content': 'Contains inappropriate or harmful content',
                'spam_scam': 'Identified as spam or scam',
                'privacy_violation': 'Violates privacy guidelines',
                'copyright_infringement': 'Copyright infringement reported',
                'impersonation': 'Impersonation reported',
                'harassment': 'Harassment or bullying reported',
                'other': 'Multiple user reports received'
            }.get(report_reason, 'Multiple user reports received')
            
            blocked_forms[form_id] = {
                'form_title': form_title,
                'event_id': event_id,
                'creator_id': creator_id,
                'reason': reason_display,
                'report_count': reports[form_id]['total_reports'],
                'blocked_at': datetime.now().isoformat(),
                'blocked_by': 'auto_system',
                'block_duration': 7,  # days
                'reports': reports[form_id]['reports_by_reason']
            }
            
            save_blocked_forms(blocked_forms)
            should_block = True
            
            log_message(f"Form {form_id} automatically blocked after {reports[form_id]['total_reports']} reports", "MODERATION")
        
        # Log the report
        log_message(f"Form {form_id} reported by {reporter_name or 'Anonymous'} ({reporter_email or 'no email'}) for: {report_reason}", "MODERATION")
        
        response_data = {
            'success': True,
            'message': 'Thank you for your report. Our moderation team will review this form shortly.',
            'blocked': should_block,
            'report_id': report_data['id']
        }
        
        if notification_sent:
            response_data['message'] += ' The moderation team has been notified.'
        
        if should_block:
            response_data['message'] += ' This form has been temporarily disabled due to multiple reports.'
        
        return jsonify(response_data)
        
    except Exception as e:
        log_message(f"Error processing form report: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/form_reports')
@login_required
@admin_required
def admin_form_reports():
    """Admin panel for form reports"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    reports = load_form_reports()
    blocked_forms = load_blocked_forms()
    
    # Calculate statistics
    total_reports = sum(form_data.get('total_reports', 0) for form_data in reports.values())
    total_forms_reported = len(reports)
    total_blocked = len(blocked_forms)
    
    # Get recent reports (last 7 days)
    recent_reports = []
    seven_days_ago = datetime.now() - timedelta(days=7)
    
    for form_id, form_data in reports.items():
        last_reported = datetime.fromisoformat(form_data.get('last_reported', datetime.now().isoformat()))
        if last_reported >= seven_days_ago:
            recent_reports.append({
                'form_id': form_id,
                'form_title': form_data.get('form_title', 'Unknown'),
                'total_reports': form_data.get('total_reports', 0),
                'last_reported': form_data.get('last_reported'),
                'is_blocked': form_id in blocked_forms
            })
    
    # Sort by last reported date
    recent_reports.sort(key=lambda x: x.get('last_reported', ''), reverse=True)
    
    return render_template('admin_form_reports.html',
                         page_title='Form Reports',
                         active_page='admin_reports',
                         reports=reports,
                         blocked_forms=blocked_forms,
                         recent_reports=recent_reports[:10],
                         total_reports=total_reports,
                         total_forms_reported=total_forms_reported,
                         total_blocked=total_blocked)

@app.route('/admin/unblock_form/<form_id>', methods=['POST'])
@login_required
@admin_required
def admin_unblock_form(form_id):
    """Unblock a form"""
    try:
        blocked_forms = load_blocked_forms()
        
        if form_id not in blocked_forms:
            return jsonify({'success': False, 'error': 'Form is not blocked'})
        
        # Get form info before removing
        form_info = blocked_forms.pop(form_id)
        
        # Save updated blocked forms
        save_blocked_forms(blocked_forms)
        
        # Send notification to creator
        users = load_users()
        creator_id = form_info.get('creator_id')
        creator_email = None
        
        if creator_id and creator_id in users:
            creator_email = users[creator_id].get('email')
        
        if creator_email:
            subject = f"✅ Form Unblocked: {form_info.get('form_title', 'Your Form')}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <div style="padding: 20px; font-family: Arial, sans-serif;">
                    <h2 style="color: #198754;">✅ Form Unblocked</h2>
                    <p>Hello,</p>
                    <p>Your form "<strong>{form_info.get('form_title', 'Unknown')}</strong>" has been reviewed and unblocked.</p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <p><strong>Form Status:</strong> <span style="color: #198754;">ACTIVE</span></p>
                        <p><strong>Unblocked At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Unblocked By:</strong> EventFlow Moderation Team</p>
                    </div>
                    <p>Your form is now accessible to users again.</p>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6;">
                        <p style="font-size: 12px; color: #6c757d;">
                            If you have any questions, please contact our support team.
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            send_email_simple(creator_email, subject, html_content)
        
        log_message(f"Form {form_id} unblocked by admin: {session.get('username')}", "MODERATION")
        return jsonify({'success': True, 'message': 'Form unblocked successfully'})
        
    except Exception as e:
        log_message(f"Error unblocking form: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/block_form/<form_id>', methods=['POST'])
@login_required
@admin_required
def admin_block_form(form_id):
    """Manually block a form"""
    try:
        data = request.json
        reason = data.get('reason', 'Manual block by admin')
        duration = data.get('duration', 7)
        
        # Find form information
        form_found = False
        form_info = {}
        
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                        event = json.load(f)
                    
                    for form in event.get('forms', []):
                        if form['id'] == form_id:
                            form_found = True
                            form_info = {
                                'form_title': form.get('title', 'Unknown'),
                                'event_id': event.get('id'),
                                'event_name': event.get('name', 'Unknown'),
                                'creator_id': event.get('creator_id')
                            }
                            break
                    
                    if form_found:
                        break
                except:
                    continue
        
        if not form_found:
            return jsonify({'success': False, 'error': 'Form not found'})
        
        # Block the form
        blocked_forms = load_blocked_forms()
        
        blocked_forms[form_id] = {
            **form_info,
            'reason': reason,
            'blocked_at': datetime.now().isoformat(),
            'blocked_by': session['user_id'],
            'blocked_by_name': session.get('username', 'Admin'),
            'block_duration': duration,
            'manual_block': True
        }
        
        save_blocked_forms(blocked_forms)
        
        log_message(f"Form {form_id} manually blocked by admin: {session.get('username')}", "MODERATION")
        return jsonify({'success': True, 'message': 'Form blocked successfully'})
        
    except Exception as e:
        log_message(f"Error blocking form: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/get_form_report_detail/<form_id>')
@login_required
@admin_required
def admin_get_form_report_detail(form_id):
    """Get detailed report information for a form"""
    try:
        reports = load_form_reports()
        blocked_forms = load_blocked_forms()
        
        if form_id not in reports:
            return jsonify({'success': False, 'error': 'No reports found for this form'})
        
        form_reports = reports[form_id]
        is_blocked = form_id in blocked_forms
        block_info = blocked_forms.get(form_id) if is_blocked else None
        
        # Get form information
        form_info = {}
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                        event = json.load(f)
                    
                    for form in event.get('forms', []):
                        if form['id'] == form_id:
                            form_info = {
                                'title': form.get('title'),
                                'questions': form.get('questions', []),
                                'created_at': form.get('created_at'),
                                'has_schedule': bool(form.get('schedule'))
                            }
                            break
                    
                    if form_info:
                        break
                except:
                    continue
        
        # Get creator information
        creator_info = {}
        creator_id = form_reports.get('creator_id')
        if creator_id:
            users = load_users()
            if creator_id in users:
                creator_info = users[creator_id]
        
        response_data = {
            'success': True,
            'form_id': form_id,
            'reports': form_reports,
            'form_info': form_info,
            'creator_info': creator_info,
            'is_blocked': is_blocked,
            'block_info': block_info
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        log_message(f"Error getting form report detail: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/clear_form_reports/<form_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_clear_form_reports(form_id):
    """Clear all reports for a form"""
    try:
        reports = load_form_reports()
        
        if form_id not in reports:
            return jsonify({'success': False, 'error': 'No reports found for this form'})
        
        # Get report count before clearing
        report_count = reports[form_id].get('total_reports', 0)
        
        # Remove the form from reports
        reports.pop(form_id)
        
        # Save updated reports
        save_form_reports(reports)
        
        log_message(f"Cleared {report_count} reports for form {form_id} by admin: {session.get('username')}", "MODERATION")
        return jsonify({
            'success': True, 
            'message': f'Cleared {report_count} reports for this form'
        })
        
    except Exception as e:
        log_message(f"Error clearing form reports: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# CRON JOB FOR CHECKING BLOCKED FORMS
# ============================================================================

def check_expired_blocks():
    """Check and automatically unblock expired forms"""
    try:
        blocked_forms = load_blocked_forms()
        unblocked_count = 0
        
        for form_id, form_info in list(blocked_forms.items()):
            blocked_at = datetime.fromisoformat(form_info.get('blocked_at', datetime.now().isoformat()))
            block_duration = form_info.get('block_duration', 7)
            
            # Check if block has expired
            if (datetime.now() - blocked_at).days >= block_duration:
                # Unblock the form
                blocked_forms.pop(form_id)
                unblocked_count += 1
                log_message(f"Form {form_id} automatically unblocked after {block_duration} days", "MODERATION")
        
        if unblocked_count > 0:
            save_blocked_forms(blocked_forms)
            log_message(f"Auto-unblocked {unblocked_count} forms", "MODERATION")
        
    except Exception as e:
        log_message(f"Error checking expired blocks: {e}", "ERROR")

# Schedule the cron job to run daily
scheduler.add_job(
    func=check_expired_blocks,
    trigger=IntervalTrigger(days=1),
    id='check_expired_blocks',
    name='Check and unblock expired forms',
    replace_existing=True
)

    
@app.route('/admin/get_user_stats')
@login_required
@admin_required
def admin_get_user_stats():
    """Get user statistics for email broadcast"""
    try:
        users = load_users()
        
        stats = {
            'total_users': len(users),
            'active_users': 0,
            'inactive_users': 0,
            'admin_users': 0,
            'with_email': 0
        }
        
        for user_data in users.values():
            if user_data.get('email'):
                stats['with_email'] += 1
            if user_data.get('is_admin'):
                stats['admin_users'] += 1
            # You could add logic for active/inactive based on last login
        
        # For now, assume all users with email are active
        stats['active_users'] = stats['with_email']
        
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        log_message(f"Error getting user stats: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/get_all_users_for_email')
@login_required
@admin_required
def admin_get_all_users_for_email():
    """Get all users for email broadcast"""
    try:
        users = load_users()
        
        include_inactive = request.args.get('include_inactive', 'true') == 'true'
        include_admin = request.args.get('include_admin', 'false') == 'true'
        
        user_list = []
        for user_id, user_data in users.items():
            # Skip users without email
            if not user_data.get('email'):
                continue
                
            # Skip admin users if not included
            if not include_admin and user_data.get('is_admin'):
                continue
                
            # Skip inactive users if not included
            # You could add logic here based on last login
            if not include_inactive:
                # Example: skip users who haven't logged in for 30 days
                pass
            
            user_list.append({
                'user_id': user_id,
                'username': user_data.get('username', 'User'),
                'email': user_data.get('email'),
                'join_date': user_data.get('created_at', '').split('T')[0],
                'is_admin': user_data.get('is_admin', False)
            })
        
        return jsonify({
            'success': True,
            'users': user_list,
            'total_users': len(user_list)
        })
        
    except Exception as e:
        log_message(f"Error getting users for email: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/send_test_broadcast_email', methods=['POST'])
@login_required
@admin_required
def admin_send_test_broadcast_email():
    """Send test broadcast email to admin"""
    try:
        data = request.json
        subject = data.get('subject')
        html_content = data.get('html_content')
        recipient_email = data.get('recipient_email', session.get('email'))
        
        if not all([subject, html_content, recipient_email]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Send the test email
        success, message = send_email_simple(recipient_email, subject, html_content)
        
        if success:
            log_message(f"Test broadcast email sent to {recipient_email}", "ADMIN")
            return jsonify({'success': True, 'message': 'Test email sent'})
        else:
            return jsonify({'success': False, 'error': message})
            
    except Exception as e:
        log_message(f"Error sending test broadcast email: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/send_batch_emails', methods=['POST'])
@login_required
@admin_required
def admin_send_batch_emails():
    """Send a batch of emails to users"""
    try:
        data = request.json
        subject = data.get('subject')
        content = data.get('content')
        sender_name = data.get('sender_name')
        users = data.get('users', [])
        batch_number = data.get('batch_number', 1)
        total_batches = data.get('total_batches', 1)
        
        if not all([subject, content, sender_name]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        sent_count = 0
        failed_count = 0
        skipped_count = 0
        failed_emails = []
        
        for user in users:
            email = user.get('email')
            username = user.get('username', 'User')
            join_date = user.get('join_date', '')
            
            if not email:
                skipped_count += 1
                continue
            
            # Personalize the content
            personalized_content = content\
                .replace('{username}', username)\
                .replace('{email}', email)\
                .replace('{join_date}', join_date)
            
            # Create HTML email
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                    .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                    .header {{ background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ padding: 30px; background: white; }}
                    .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                    .unsubscribe {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 11px; color: #6c757d; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>📢 EventFlow Announcement</h2>
                    </div>
                    <div class="content">
                        {personalized_content.replace('\n', '<br>')}
                        <div class="footer">
                            <p>Sent by: <strong>{sender_name}</strong></p>
                            <p>This is an automated message from EventFlow.</p>
                        </div>
                        <div class="unsubscribe">
                            <p>You received this email because you're registered with EventFlow.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Send the email
            success, message = send_email_simple(email, subject, html_content)
            
            if success:
                sent_count += 1
                log_message(f"Broadcast email sent to {email} (Batch {batch_number}/{total_batches})", "ADMIN")
            else:
                failed_count += 1
                failed_emails.append(email)
                log_message(f"Failed to send broadcast email to {email}: {message}", "ERROR")
            
            # Small delay to avoid rate limiting
            import time
            time.sleep(0.5)
        
        return jsonify({
            'success': True,
            'batch_number': batch_number,
            'total_batches': total_batches,
            'sent_count': sent_count,
            'failed_count': failed_count,
            'skipped_count': skipped_count,
            'failed_emails': failed_emails[:10],  # Limit to first 10 failed emails
            'message': f'Sent {sent_count} emails in batch {batch_number}'
        })
        
    except Exception as e:
        log_message(f"Error sending batch emails: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})
    
    
# ============================================================================
# FORM URL CHECKING ROUTES
# ============================================================================

@app.route('/check_form_url/<form_id>')
@login_required
def check_form_url(form_id):
    """Check if form URL is accessible"""
    result = {
        'form_id': form_id,
        'url': url_for('show_form', form_id=form_id, _external=True),
        'accessible': False,
        'status_code': None,
        'error': None
    }
    
    try:
        import requests
        response = requests.head(result['url'], timeout=10)
        result['status_code'] = response.status_code
        result['accessible'] = response.status_code == 200
    except Exception as e:
        result['error'] = str(e)
    
    return jsonify(result)

# ============================================================================
# DEBUG ROUTES FOR TESTING
# ============================================================================

@app.route('/debug-session')
def debug_session():
    """Debug session data"""
    debug_info = {
        'session_keys': list(session.keys()),
        'verify_email': session.get('verify_email'),
        'pending_user': session.get('pending_user'),
        'user_id': session.get('user_id'),
        'email': session.get('email')
    }
    
    # Check OTP storage
    try:
        from otp import _load_otp_store
        store = _load_otp_store()
        debug_info['otp_store_size'] = len(store)
        debug_info['otp_store_emails'] = list(store.keys())
    except:
        debug_info['otp_store'] = 'Error loading'
    
    return jsonify(debug_info)

@app.route('/debug-routes')
def debug_routes():
    """List all routes for debugging"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': str(rule)
        })
    
    # Sort by endpoint
    routes.sort(key=lambda x: x['endpoint'])
    
    # Find duplicates
    endpoints = {}
    duplicates = []
    for route in routes:
        if route['endpoint'] in endpoints:
            duplicates.append(route['endpoint'])
        else:
            endpoints[route['endpoint']] = True
    
    return jsonify({
        'total_routes': len(routes),
        'duplicates': duplicates,
        'routes': routes
    })

# ============================================================================
# MULTI-PAGE FEEDBACK FORM ROUTES (if referenced)
# ============================================================================

@app.route('/feedback/multi/<int:current_page>', methods=['GET', 'POST'])
def multi_page_feedback(current_page):
    """Multi-page feedback form - redirect to regular feedback"""
    flash('Multi-page feedback is temporarily unavailable. Using regular feedback form.', 'info')
    return redirect(url_for('feedback'))

@app.route('/feedback/multi/submit', methods=['POST'])
def submit_multi_page_feedback():
    """Submit multi-page feedback - redirect"""
    return redirect(url_for('feedback'))

# ============================================================================
# DIAGNOSTIC TOOLS (add these if missing)
# ============================================================================

@app.route('/check_email_config')
@login_required
def check_email_config():
    """Check email configuration"""
    config_info = {
        'MAIL_USERNAME': MAIL_USERNAME,
        'MAIL_PASSWORD': '***' + (MAIL_PASSWORD[-4:] if MAIL_PASSWORD else 'NONE'),
        'MAIL_SERVER': MAIL_SERVER,
        'MAIL_PORT': MAIL_PORT,
        'MAIL_FROM': MAIL_FROM,
        'Password Length': len(MAIL_PASSWORD) if MAIL_PASSWORD else 0
    }
    
    # Try to connect to SMTP server
    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        config_info['SMTP_Connection'] = '✅ Connected successfully'
        server.quit()
    except Exception as e:
        config_info['SMTP_Connection'] = f'❌ Failed: {str(e)}'
    
    return render_template('email_config.html', config=config_info)

@app.route('/view_email_log')
@login_required
def view_email_log():
    """View email log file"""
    try:
        with open('logs/email.log', 'r') as f:
            log_content = f.read()
    except:
        log_content = "Log file not found or empty."
    
    return render_template('email_log.html', log_content=log_content)

@app.route('/admin/check_my_status')
@login_required
def check_my_status():
    """Check if current user is blocked"""
    users = load_users()
    user_id = session.get('user_id')
    
    if user_id not in users:
        return jsonify({
            'success': False,
            'blocked': True,
            'message': 'User not found'
        })
    
    user_data = users[user_id]
    
    if user_data.get('blocked', False):
        # Auto-logout if blocked
        session.clear()
        return jsonify({
            'success': False,
            'blocked': True,
            'message': 'Account blocked'
        })
    
    return jsonify({
        'success': True,
        'user': {
            'blocked': user_data.get('blocked', False),
            'is_admin': user_id == 'admin' or user_data.get('is_admin', False)
        }
    })

@app.route('/email_debug_info')
@login_required
def email_debug_info():
    """Show detailed email configuration comparison"""
    config = {
        'test_email': {
            'function': 'send_email_simple()',
            'sender': MAIL_USERNAME,
            'recipient': MAIL_USERNAME,
            'subject_format': '"📋 Registration: {form_title}"',
            'content': 'Full HTML with styling',
            'threading': 'No threading',
            'delay': 'No delay between emails'
        },
        'real_email': {
            'function': 'send_email_simple()',
            'sender': MAIL_USERNAME,
            'recipient': 'Form recipients',
            'subject_format': '"📋 Registration: {form_title}"',
            'content': 'Full HTML with styling',
            'threading': 'No threading (in direct mode)',
            'delay': '1 second between emails'
        },
        'config_identical': 'YES - Both use identical SMTP settings and send_email_simple() function',
        'differences': 'Only recipient and minor content variations'
    }
    
    # Check if both would work
    try:
        import smtplib
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        config['smtp_connection'] = '✅ SUCCESS'
        server.quit()
    except Exception as e:
        config['smtp_connection'] = f'❌ FAILED: {str(e)[:100]}'
    
    return render_template('email_debug_info.html', config=config)

@app.route('/compare_email_test')
@login_required
def compare_email_test():
    """Send both test and real-style emails to compare"""
    try:
        if not MAIL_USERNAME or not MAIL_PASSWORD:
            flash('❌ Email not configured', 'error')
            return redirect(url_for('dashboard'))
        
        log_message("🔬 COMPARING TEST vs REAL EMAIL CONFIGURATIONS", "INFO")
        
        # Test 1: Simple test email
        simple_success, simple_msg = send_email_simple(
            MAIL_USERNAME,
            "Simple Test Email",
            "<h2>Simple Test</h2><p>This is a basic test email.</p>"
        )
        
        # Wait 2 seconds
        import time
        time.sleep(2)
        
        # Test 2: Real-style email (identical to form invitations)
        form_url = url_for('index', _external=True)
        form_title = "Test Registration Form"
        event_name = "Test Event"
        sender_name = session.get('username', 'User')
        
        real_success, real_msg = send_email_simple(
            MAIL_USERNAME,
            f"📋 Registration: {form_title}",
            f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <h2>Real-Style Test Email</h2>
                <p><strong>Event:</strong> {event_name}</p>
                <p><strong>Form:</strong> {form_title}</p>
                <p><a href="{form_url}">Register Now</a></p>
                <p><code>{form_url}</code></p>
                <p>From: {sender_name}</p>
            </body>
            </html>
            """
        )
        
        # Show comparison results
        if simple_success and real_success:
            flash('✅ BOTH email types sent successfully!', 'success')
            flash('🔍 Configuration is identical for both test and real emails.', 'info')
            flash('🔧 If real form emails fail, check form URL generation.', 'info')
        elif not simple_success and not real_success:
            flash('❌ BOTH email types failed with same error.', 'error')
            flash(f'🔍 Error: {simple_msg}', 'error')
            flash('🔧 Fix your SMTP configuration in .env file.', 'error')
        elif simple_success and not real_success:
            flash('⚠️ SIMPLE email works but REAL email fails!', 'warning')
            flash(f'🔍 Simple worked, but real failed: {real_msg}', 'warning')
            flash('🔧 This means the issue is in the CONTENT, not the configuration.', 'info')
        elif not simple_success and real_success:
            flash('⚠️ REAL email works but SIMPLE email fails!', 'warning')
            flash(f'🔍 Real worked, but simple failed: {simple_msg}', 'warning')
            flash('🔧 This is unusual - check email content differences.', 'info')
            
    except Exception as e:
        flash(f'❌ Comparison test error: {str(e)[:100]}', 'error')
    
    return redirect(url_for('dashboard'))

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def log_message(message, level="INFO"):
    """Log messages with levels"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [{level}] {message}"
    print(log_entry)
    with open('logs/email.log', 'a', encoding='utf-8') as f:
        f.write(log_entry + '\n')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_users(users):
    with open(get_data_path('users.json'), 'w') as f:
        json.dump(users, f, indent=4)

def load_event(event_id):
    try:
        with open(get_data_path(f'events/{event_id}.json'), 'r') as f:
            return json.load(f)
    except:
        return None

def save_event(event_data):
    os.makedirs(get_data_path('events'), exist_ok=True)
    path = get_data_path(f"events/{event_data['id']}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(event_data, f, indent=4)

def save_email_status(user_id, status_data):
    """Save email status for user"""
    try:
        status_file = f'data/email_status/{user_id}.json'
        os.makedirs('data/email_status', exist_ok=True)
        with open(status_file, 'w') as f:
            json.dump(status_data, f, indent=4)
    except Exception as e:
        log_message(f"Failed to save email status: {e}", "ERROR")

def load_email_status(user_id):
    """Load email status for user"""
    try:
        status_file = f'data/email_status/{user_id}.json'
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def get_user_events_count(user_id):
    """Get count of events created by user"""
    count = 0
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    if event.get('creator_id') == user_id:
                        count += 1
            except:
                continue
    return count

def get_user_forms_count(user_id):
    """Get count of forms created by user"""
    count = 0
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    if event.get('creator_id') == user_id:
                        count += len(event.get('forms', []))
            except:
                continue
    return count

def allowed_file_with_settings(file, file_settings):
    """Check if file is allowed based on question settings"""
    if not file or not file.filename:
        return False
    
    # Get file extension
    filename = file.filename
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    # Check file size
    if file_settings:
        max_size_mb = file_settings.get('max_size_mb', 16)
        
        # Get file size by reading content
        file.seek(0, 2)  # Seek to end to get file size
        file_size_mb = file.tell() / (1024 * 1024)
        file.seek(0)  # Reset file pointer
        
        if file_size_mb > max_size_mb:
            return False
        
        # Check allowed types
        allowed_types = file_settings.get('allowed_types', [])
        if allowed_types:
            # Get categorized file types
            file_categories = get_file_type_categories()
            
            # Check if extension is in any allowed category
            for category_id in allowed_types:
                if category_id in file_categories:
                    if ext in file_categories[category_id]['extensions']:
                        return True
            
            # If we get here, file type not allowed
            return False
    
    # If no specific settings, use default allowed extensions
    return ext in ALLOWED_EXTENSIONS

def generate_qr_code(url):
    """Generate clean QR code with EventFlow logo in the center - NO black borders"""
    try:
        # Check if logo exists
        logo_path = 'static/logo/icon.png'
        has_logo = os.path.exists(logo_path)
        
        # Create QR code with better error correction for logo
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,  # Optimal size
            border=0,     # Smaller border
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        # Create QR code image with light blue color
        qr_img = qr.make_image(fill_color="#4a6cf7", back_color="white").convert('RGB')
        
        if has_logo:
            try:
                from PIL import Image
                # Open logo
                logo = Image.open(logo_path)
                
                # Get QR code dimensions
                qr_width, qr_height = qr_img.size
                
                # Calculate logo size - 25% of smallest QR dimension
                logo_size = int(min(qr_width, qr_height) * 0.25)
                
                # Resize logo
                logo.thumbnail((logo_size, logo_size), Image.Resampling.LANCZOS)
                
                # Calculate position to center logo
                pos = ((qr_width - logo.size[0]) // 2, (qr_height - logo.size[1]) // 2)
                
                # Check if logo has transparency
                if logo.mode == 'RGBA':
                    # Handle transparent logo - paste directly
                    # Create a temporary image to blend with QR background
                    temp_img = Image.new('RGBA', qr_img.size, (0, 0, 0, 0))
                    temp_img.paste(qr_img, (0, 0))
                    
                    # Create logo with white background for better visibility
                    logo_bg = Image.new('RGBA', logo.size, (255, 255, 255, 230))  # Semi-transparent white
                    
                    # Composite logo on white background
                    logo_on_bg = Image.alpha_composite(logo_bg, logo)
                    
                    # Paste logo onto temporary image
                    temp_img.paste(logo_on_bg, pos, logo_on_bg)
                    
                    # Convert back to RGB
                    qr_img = temp_img.convert('RGB')
                else:
                    # Logo has no transparency, add clean white circle background
                    from PIL import ImageDraw
                    
                    # Create a new image for the logo with white circle
                    logo_with_bg = Image.new('RGBA', (logo_size, logo_size), (0, 0, 0, 0))
                    draw = ImageDraw.Draw(logo_with_bg)
                    
                    # Draw white circle (not rectangle) for cleaner look
                    circle_margin = 2
                    circle_size = logo_size - circle_margin * 2
                    draw.ellipse(
                        [circle_margin, circle_margin, 
                         circle_margin + circle_size, circle_margin + circle_size],
                        fill=(255, 255, 255, 255)  # Pure white, no border
                    )
                    
                    # Calculate position for logo inside circle
                    logo_pos = (
                        (logo_size - logo.size[0]) // 2,
                        (logo_size - logo.size[1]) // 2
                    )
                    
                    # Paste logo onto circle background
                    logo_with_bg.paste(logo, logo_pos)
                    
                    # Convert to RGB
                    logo_with_bg_rgb = logo_with_bg.convert('RGB')
                    
                    # Paste onto QR code
                    qr_img.paste(logo_with_bg_rgb, (
                        (qr_width - logo_size) // 2,
                        (qr_height - logo_size) // 2
                    ))
                
            except Exception as e:
                log_message(f"Error adding logo to QR code: {e}", "WARNING")
                # Use text logo instead
                return generate_qr_code_with_text(url)
        else:
            # Use text-based logo
            return generate_qr_code_with_text(url)
        
        # Convert to base64
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG", optimize=True)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
        
    except Exception as e:
        log_message(f"QR Code error: {e}", "ERROR")
        return generate_simple_qr_code(url)

def generate_qr_code_with_text(url):
    """Generate QR code with text logo - NO black borders"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="#4a6cf7", back_color="white").convert('RGB')
        qr_width, qr_height = qr_img.size
        
        # Create drawing context
        draw = ImageDraw.Draw(qr_img)
        
        # Calculate circle size for background
        circle_size = int(min(qr_width, qr_height) * 0.22)  # Smaller circle
        left = (qr_width - circle_size) // 2
        top = (qr_height - circle_size) // 2
        
        # Draw white circle WITHOUT any border
        draw.ellipse(
            [left, top, left + circle_size, top + circle_size],
            fill="white"  # No outline parameter = no border
        )
        
        # Font size for text
        font_size = int(circle_size * 0.5)
        
        # Try to find a nice font
        font = None
        try:
            # Try to load a bold font
            font_paths = [
                '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
                '/System/Library/Fonts/Helvetica.ttc',
                'C:\\Windows\\Fonts\\Arial.ttf',
                'arialbd.ttf',
                'arial.ttf'
            ]
            
            for font_path in font_paths:
                if os.path.exists(font_path):
                    try:
                        font = ImageFont.truetype(font_path, font_size)
                        break
                    except:
                        continue
        except:
            pass
        
        if not font:
            # Use default font
            font = ImageFont.load_default()
        
        # Draw "EF" text in blue
        text = "EF"
        
        # Calculate text position
        try:
            # Get text bounding box
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        except:
            text_width = len(text) * font_size // 2
            text_height = font_size
        
        text_x = left + (circle_size - text_width) // 2
        text_y = top + (circle_size - text_height) // 2
        
        # Draw text in blue
        draw.text((text_x, text_y), text, fill="#4a6cf7", font=font)
        
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG", optimize=True)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
        
    except Exception as e:
        log_message(f"Text QR Code error: {e}", "ERROR")
        return generate_simple_qr_code(url)

def generate_simple_qr_code(url):
    """Generate simple QR code without logo"""
    try:
        qr = qrcode.QRCode(
            version=1,
            box_size=8,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#4a6cf7", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        log_message(f"Simple QR Code error: {e}", "ERROR")
        return None

def get_server_statistics():
    """Get real statistics from the server"""
    stats = {
        'users': 0,
        'events': 0,
        'forms': 0,
        'registrations': 0
    }
    
    # Count users
    try:
        users = load_users()
        stats['users'] = len(users)
    except:
        stats['users'] = 0
    
    # Count events
    try:
        event_files = [f for f in os.listdir('data/events') if f.endswith('.json')]
        stats['events'] = len(event_files)
        
        # Count forms and registrations
        for event_file in event_files:
            try:
                with open(f'data/events/{event_file}', 'r') as f:
                    event = json.load(f)
                    stats['forms'] += len(event.get('forms', []))
                    
                    # Count registrations for each form
                    for form in event.get('forms', []):
                        csv_path = f'data/events/{event["id"]}/{form["id"]}.csv'
                        if os.path.exists(csv_path):
                            with open(csv_path, 'r') as csv_file:
                                reader = csv.reader(csv_file)
                                stats['registrations'] += max(0, len(list(reader)) - 1)
            except:
                continue
    except:
        pass
    
    return stats

# ============================================================================
# FORM SCHEDULING FUNCTIONS
# ============================================================================

def schedule_form_notification(event_id, form_id, form_title, end_datetime_str, event_name, user_id, user_email):
    """Schedule email notification for when form ends"""
    try:
        # Parse end datetime
        end_datetime = datetime.fromisoformat(end_datetime_str.replace('T', ' ') if 'T' in end_datetime_str else end_datetime_str)
        
        # Calculate when to send notification (immediately after end time)
        notification_time = end_datetime
        
        # Store notification in a file for cron job or scheduler
        notification_data = {
            'event_id': event_id,
            'form_id': form_id,
            'form_title': form_title,
            'event_name': event_name,
            'user_id': user_id,
            'user_email': user_email,
            'end_datetime': end_datetime_str,
            'notification_time': notification_time.isoformat(),
            'created_at': datetime.now().isoformat(),
            'sent': False
        }
        
        # Create notifications directory
        os.makedirs('data/form_notifications', exist_ok=True)
        
        # Save notification
        notification_file = f'data/form_notifications/{form_id}.json'
        with open(notification_file, 'w', encoding='utf-8') as f:
            json.dump(notification_data, f, indent=2)
        
        log_message(f"📅 Form end notification scheduled for {form_title} at {notification_time}", "INFO")
        
        # Also add to event file for immediate checking
        event = load_event(event_id)
        if event:
            for form in event.get('forms', []):
                if form['id'] == form_id:
                    if form.get('schedule'):
                        form['schedule']['notification_scheduled'] = True
                    break
            save_event(event)
        
        return True
    except Exception as e:
        log_message(f"Error scheduling form notification: {e}", "ERROR")
        return False

def send_form_end_notification(event_id, form_id, form_title, event_name, user_email, username, response_count):
    """Send email notification when form ends"""
    try:
        subject = f"📋 Form Closed: {form_title}"
        
        # MANUAL URLS
        base_url = "https://overpotent-bianca-foamy.ngrok-free.dev"
        form_view_url = f"{base_url}/view_form/{event_id}/{form_id}"
        download_csv_url = f"{base_url}/download_csv/{event_id}/{form_id}"
        download_pdf_url = f"{base_url}/generate_pro_pdf/{event_id}/{form_id}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .stats-box {{ background: #f0efff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .action-buttons {{ margin: 25px 0; }}
                .btn {{ display: inline-block; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 5px; }}
                .btn-primary {{ background: #4361ee; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📋 Form Closed</h1>
                    <p>Your form has reached its end date</p>
                </div>
                <div class="content">
                    <p>Hi {username},</p>
                    
                    <p>Your form <strong>"{form_title}"</strong> for event <strong>"{event_name}"</strong> has now closed as scheduled.</p>
                    
                    <div class="stats-box">
                        <h3>📊 Form Summary</h3>
                        <p><strong>Form Title:</strong> {form_title}</p>
                        <p><strong>Event:</strong> {event_name}</p>
                        <p><strong>Total Responses:</strong> {response_count}</p>
                        <p><strong>Closed At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <p><strong>📈 View Your Data:</strong></p>
                    <p>You can now review all submissions and analyze the collected data.</p>
                    
                    <div class="action-buttons">
                        <p><strong>Quick Actions:</strong></p>
                        <a href="{form_view_url}" class="btn btn-primary">
                            <i class="bi bi-eye"></i> View Form & Responses
                        </a>
                        <a href="{download_csv_url}" class="btn btn-secondary">
                            <i class="bi bi-download"></i> Download as CSV
                        </a>
                        <a href="{download_pdf_url}" class="btn btn-secondary">
                            <i class="bi bi-file-pdf"></i> Download as PDF
                        </a>
                    </div>
                    
                    <div style="background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <p><strong>📝 Next Steps:</strong></p>
                        <ul>
                            <li>Review all responses in the form dashboard</li>
                            <li>Download data for further analysis</li>
                            <li>Generate reports for stakeholders</li>
                            <li>Archive or delete the form if no longer needed</li>
                        </ul>
                    </div>
                    
                    <p>Need help analyzing your data? Contact our support team for assistance.</p>
                    
                    <div class="footer">
                        <p>This is an automated notification from EventFlow Form System.</p>
                        <p>© {datetime.now().year} EventFlow. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email
        success, message = send_email_simple(user_email, subject, html_content)
        
        if success:
            log_message(f"Form end notification sent to {user_email} for form {form_id}", "INFO")
            return True
        else:
            log_message(f"Failed to send form end notification: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"Error sending form end notification: {e}", "ERROR")
        return False

def get_real_ip_simple():
    """Simplified version that prefers IPv4"""
    # Try X-Forwarded-For first (common proxy header)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Get first IP in the chain
        ip = x_forwarded_for.split(',')[0].strip()
        if ip and ip != 'unknown':
            # Check if it's IPv4
            if '.' in ip and ':' not in ip:
                return ip  # Likely IPv4
            # If it's IPv6-mapped IPv4
            elif ip.startswith('::ffff:'):
                return ip.split(':')[-1]  # Extract IPv4 part
    
    # Try X-Real-IP
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        if '.' in x_real_ip and ':' not in x_real_ip:
            return x_real_ip
    
    # Fallback - check if remote_addr is IPv6
    remote_ip = request.remote_addr or '0.0.0.0'
    if ':' in remote_ip:
        # Check if it's IPv6-mapped IPv4
        if remote_ip.startswith('::ffff:'):
            return remote_ip.split(':')[-1]
        # Pure IPv6
        return f"[IPv6:{remote_ip}]"
    
    return remote_ip
def check_ended_forms(app):
    """Check for forms that have ended and send notifications if needed"""
    with app.app_context():
        try:
            log_message("🔍 Checking for ended forms...", "INFO")
            
            ended_forms = []
            notification_count = 0
            
            for filename in os.listdir('data/events'):
                if filename.endswith('.json'):
                    try:
                        with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                            event = json.load(f)
                        
                        event_id = event.get('id')
                        event_name = event.get('name')
                        
                        for form in event.get('forms', []):
                            form_id = form.get('id')
                            form_title = form.get('title')
                            schedule = form.get('schedule')
                            
                            if schedule and schedule.get('end_datetime'):
                                end_datetime_str = schedule.get('end_datetime')
                                
                                try:
                                    end_datetime = datetime.fromisoformat(
                                        end_datetime_str.replace('T', ' ') if 'T' in end_datetime_str else end_datetime_str
                                    )
                                    now = datetime.now()
                                    
                                    if now >= end_datetime:
                                        notification_sent = schedule.get('notification_sent', False)
                                        
                                        if not notification_sent:
                                            csv_path = f'data/events/{event_id}/{form_id}.csv'
                                            response_count = 0
                                            if os.path.exists(csv_path):
                                                try:
                                                    with open(csv_path, 'r', encoding='utf-8') as csv_file:
                                                        reader = csv.reader(csv_file)
                                                        response_count = max(0, len(list(reader)) - 1)
                                                except:
                                                    response_count = 0
                                            
                                            # Strict check for notification enabled
                                            notify_on_end = schedule.get('notify_on_end') == True
                                            
                                            log_message(f"🔍 Form '{form_title}': notify_on_end = {schedule.get('notify_on_end')}, will send = {notify_on_end}", "DEBUG")
                                            
                                            if notify_on_end:
                                                user_id = event.get('creator_id')
                                                user_email = None
                                                username = "Event Organizer"
                                                
                                                users = load_users()
                                                if user_id in users:
                                                    user_data = users[user_id]
                                                    user_email = user_data.get('email')
                                                    username = user_data.get('username', username)
                                                
                                                if user_email:
                                                    log_message(f"📧 Sending notification to {user_email} for '{form_title}'", "INFO")
                                                    
                                                    sent = send_form_end_notification(
    event_id, form_id, form_title, event_name,
    user_email, username, response_count
)
                                                    
                                                    if sent:
                                                        # Mark as sent and SAVE TO DISK
                                                        for f in event['forms']:
                                                            if f['id'] == form_id:
                                                                sched = f.get('schedule', {})
                                                                sched['notification_sent'] = True
                                                                sched['notification_sent_at'] = now.isoformat()
                                                                sched['response_count_at_end'] = response_count
                                                                break
                                                        
                                                        save_event(event)
                                                        
                                                        notification_count += 1
                                                        log_message(f"✅ Notification sent and saved for '{form_title}'", "SUCCESS")
                                                    else:
                                                        log_message(f"❌ Failed to send notification for '{form_title}'", "ERROR")
                                                else:
                                                    log_message(f"❌ No email for creator (user_id: {user_id})", "ERROR")
                                            else:
                                                log_message(f"ℹ️ Notification disabled for '{form_title}'", "INFO")
                                            
                                            ended_forms.append({
                                                'event_id': event_id,
                                                'form_id': form_id,
                                                'form_title': form_title,
                                            })
                                    
                                except Exception as parse_error:
                                    log_message(f"Error parsing datetime for form {form_id}: {parse_error}", "ERROR")
                                    
                    except Exception as e:
                        log_message(f"Error processing event file {filename}: {e}", "ERROR")
            
            log_message(f"📊 Check complete: {notification_count} notification(s) sent", "INFO")
            
        except Exception as e:
            log_message(f"Critical error in check_ended_forms: {e}", "ERROR")
            return []

# Schedule form end checking every 5 minutes
#scheduler.add_job(
#    func=check_ended_forms,
#    trigger=IntervalTrigger(minutes=5),
#    id='check_ended_forms',
#    name='Check for ended forms and send notifications',
#    replace_existing=True
#)

# Start the scheduler when app starts
#scheduler.start()

# Make sure to shutdown scheduler when app stops
import atexit
# Only shutdown if scheduler is running
atexit.register(lambda: scheduler.shutdown() if scheduler.running else None)
            
# Schedule form end checking every 5 minutes
def schedule_check_ended_forms(app):
    """Wrapper function to pass app to check_ended_forms"""
    return check_ended_forms(app)

scheduler.add_job(
    func=lambda: schedule_check_ended_forms(app),  # Pass app instance
    trigger=IntervalTrigger(minutes=5),
    id='check_ended_forms',
    name='Check for ended forms and send notifications',
    replace_existing=True
)

# Start the scheduler when app starts
scheduler.start()

# Make sure to shutdown scheduler when app stops
import atexit
atexit.register(lambda: scheduler.shutdown())
            

# ============================================================================
# SIMPLIFIED EMAIL FUNCTIONS
# ============================================================================

def send_email_simple(to_email, subject, html_content):
    """Send email using Resend API"""
    try:
        import resend
        
        RESEND_API_KEY = os.environ.get('RESEND_API_KEY')
        
        if not RESEND_API_KEY:
            error_msg = "RESEND_API_KEY not found."
            log_message(f"❌ {error_msg}", "ERROR")
            return False, error_msg
        
        resend.api_key = RESEND_API_KEY
        
        # Use sender from environment (now onboarding@resend.dev)
        from_email = os.environ.get('MAIL_DEFAULT_SENDER', 'EventFlow <onboarding@resend.dev>')
        
        params = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }
        
        email_response = resend.Emails.send(params)
        
        if email_response and 'id' in email_response:
            log_message(f"✅ Email sent to {to_email} | ID: {email_response['id']}", "SUCCESS")
            return True, "Email sent successfully"
        else:
            error_msg = f"Resend API Error: {str(email_response)}"
            log_message(f"❌ {error_msg}", "ERROR")
            return False, error_msg
            
    except Exception as e:
        error_msg = f"Email error: {str(e)}"
        log_message(f"❌ {error_msg}", "ERROR")
        return False, error_msg
        
        
def send_emails_direct(recipient_emails, form_url, form_title, event_name, sender_name, custom_message):
    """Send emails directly (no threading)"""
    results = []
    
    for idx, email in enumerate(recipient_emails):
        email = email.strip()
        
        # Skip invalid emails
        if not email or '@' not in email or '.' not in email:
            results.append({'email': email, 'status': 'invalid', 'message': 'Invalid email format'})
            continue
        
        # Prepare email
        subject = f"📋 Registration: {form_title}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .btn {{ background: #4361ee; color: white; padding: 12px 24px; text-decoration: none; 
                        border-radius: 6px; display: inline-block; margin: 20px 0; }}
                .custom-message {{ background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📋 Event Registration Invitation</h1>
                </div>
                <div style="padding: 30px;">
                    <p>Hello,</p>
                    
                    <p>You're invited to register for:</p>
                    <h2>{event_name}</h2>
                    <p><strong>Form:</strong> {form_title}</p>
                    
                    {f'<div class="custom-message"><p><strong>Message from {sender_name}:</strong><br>{custom_message}</p></div>' if custom_message else ''}
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="{form_url}" class="btn">📝 Register Now</a>
                    </div>
                    
                    <p>Or copy this link:</p>
                    <div style="background: #f1f5f9; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <code>{form_url}</code>
                    </div>
                    
                    <p>Sent by: <strong>{sender_name}</strong></p>
                    
                    <div class="footer">
                        <p>EventFlow Registration System</p>
                        <p>© {datetime.now().year}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Use the SAME function as test_email
        success, message = send_email_simple(email, subject, html_content)
        
        if success:
            results.append({'email': email, 'status': 'sent', 'message': message})
        else:
            results.append({'email': email, 'status': 'failed', 'message': message})
        
        # Small delay
        import time
        if idx < len(recipient_emails) - 1:
            time.sleep(1)
    
    return results

# ============================================================================
# FEEDBACK HELPER FUNCTIONS
# ============================================================================

def load_feedback():
    """Load feedback from JSON file"""
    try:
        os.makedirs('data', exist_ok=True)
        feedback_file = 'data/feedback.json'
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log_message(f"Error loading feedback: {e}", "ERROR")
    return []

def save_feedback(feedback_data):
    """Save feedback to JSON file"""
    try:
        feedback_file = 'data/feedback.json'
        with open(feedback_file, 'w', encoding='utf-8') as f:
            json.dump(feedback_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        log_message(f"Error saving feedback: {e}", "ERROR")
        return False

def send_thank_you_email(to_email, name, feedback_id, feedback_type, rating, message):
    """Send thank you email to user after feedback submission"""
    try:
        subject = "🎉 Thank You for Your Feedback!"
        
        # Create personalized message based on feedback type
        type_messages = {
            'suggestion': "We appreciate your suggestion and will consider it in our planning.",
            'bug': "We'll investigate the issue you reported and work on fixing it.",
            'praise': "Your kind words motivate us to keep improving!",
            'general': "We value your feedback and will use it to improve EventFlow.",
            'feature': "Great idea! We'll add this to our feature consideration list."
        }
        
        type_message = type_messages.get(feedback_type, "We appreciate your feedback!")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #6C63FF 0%, #3f37c9 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .feedback-summary {{ background: #f0efff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .rating-stars {{ color: #ffc107; font-size: 20px; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .status-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; background: #d1fae5; color: #059669; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Thank You!</h1>
                    <p>Your feedback helps us improve EventFlow</p>
                </div>
                <div class="content">
                    <p>Hi {name},</p>
                    
                    <p>Thank you for taking the time to share your feedback with us. We truly appreciate you helping us improve EventFlow.</p>
                    
                    <div class="feedback-summary">
                        <p><strong>📋 Your Feedback Summary:</strong></p>
                        <div class="d-flex align-items-center mb-2">
                            <div class="rating-stars">
                                {'★' * rating}{'☆' * (5 - rating)}
                            </div>
                            <span class="ms-3"><strong>{rating}/5</strong> Rating</span>
                        </div>
                        <p><strong>Type:</strong> <span class="status-badge">{feedback_type.replace('_', ' ').title()}</span></p>
                        <p><strong>Reference ID:</strong> {feedback_id}</p>
                        <p><strong>Submitted:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div style="background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <p><strong>📝 Your Message:</strong></p>
                        <p style="font-style: italic;">"{message[:200]}{'...' if len(message) > 200 else ''}"</p>
                    </div>
                    
                    <p><strong>What happens next?</strong></p>
                    <ul>
                        <li>Our team will review your feedback within 24-48 hours</li>
                        <li>We'll use your insights to improve EventFlow</li>
                        <li>{type_message}</li>
                        <li>If you requested contact, we may follow up for more details</li>
                    </ul>
                    
                    <p>You can view and track your feedback submissions in your dashboard.</p>
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="{url_for('dashboard', _external=True)}" style="background: #6C63FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
                            <i class="bi bi-speedometer2"></i> Go to Dashboard
                        </a>
                    </div>
                    
                    <p>If you have additional thoughts, feel free to reply to this email.</p>
                    
                    <p>Best regards,<br>The EventFlow Team</p>
                    
                    <div class="footer">
                        <p>This is an automated message. Please do not reply to this email.</p>
                        <p>© {datetime.now().year} EventFlow. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email
        success, message = send_email_simple(to_email, subject, html_content)
        if success:
            log_message(f"Thank you email sent to {to_email}", "INFO")
            return True
        else:
            log_message(f"Failed to send thank you email: {message}", "ERROR")
            return False
            
    except Exception as e:
        log_message(f"Error sending thank you email: {e}", "ERROR")
        return False

def calculate_feedback_stats(feedback_data):
    """Calculate feedback statistics"""
    total = len(feedback_data)
    unread_count = sum(1 for fb in feedback_data if fb.get('status') == 'new')
    
    # Average rating
    ratings = [fb.get('rating', 0) for fb in feedback_data if fb.get('rating', 0) > 0]
    average_rating = sum(ratings) / len(ratings) if ratings else 0
    
    # This month count
    today = datetime.now()
    this_month_count = 0
    for fb in feedback_data:
        fb_date = datetime.fromisoformat(fb.get('timestamp', '2000-01-01'))
        if fb_date.year == today.year and fb_date.month == today.month:
            this_month_count += 1
    
    return {
        'total_feedback': total,
        'unread_count': unread_count,
        'average_rating': average_rating,
        'this_month': this_month_count
    }

# ============================================================================
# VIDEO FILE DISCOVERY FUNCTION
# ============================================================================

def find_video_file(step):
    """Find video file for a specific step, regardless of naming convention"""
    video_dir = 'static/videos/how-it-works'
    
    if not os.path.exists(video_dir):
        return None
    
    # List of possible filename patterns to try
    patterns = [
        f"step-{step}.mp4",
        f"step-{step}.webm",
        f"step-{step}.mov",
        f"step{step}.mp4",
        f"step{step}.webm",
        f"step{step}.mov",
        f"step_{step}.mp4",
        f"step_{step}.webm",
        f"step_{step}.mov",
    ]
    
    # First, try exact patterns
    for pattern in patterns:
        filepath = os.path.join(video_dir, pattern)
        if os.path.exists(filepath):
            return filepath
    
    # Also look for any file that starts with stepX (case insensitive)
    for filename in os.listdir(video_dir):
        filename_lower = filename.lower()
        
        # Check for patterns like step1, step-1, step_1
        step_patterns = [f"step{step}", f"step-{step}", f"step_{step}"]
        for pattern in step_patterns:
            if pattern in filename_lower:
                if any(filename_lower.endswith(ext) for ext in ['.mp4', '.webm', '.mov', '.avi', '.mkv']):
                    return os.path.join(video_dir, filename)
    
    # If no pattern matches, try to get the first file that might be for this step
    all_video_files = []
    for filename in os.listdir(video_dir):
        if any(filename.lower().endswith(ext) for ext in ['.mp4', '.webm', '.mov', '.avi', '.mkv']):
            all_video_files.append(filename)
    
    # Sort files naturally
    all_video_files.sort()
    
    # Try to get file by index (step 1 = first file, step 2 = second file, etc.)
    if 0 <= step - 1 < len(all_video_files):
        return os.path.join(video_dir, all_video_files[step - 1])
    
    return None

def send_feedback_notification(feedback):
    """Send email notification about new feedback"""
    try:
        # Load settings
        settings_file = 'data/feedback_settings.json'
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        else:
            # Default settings
            settings = {'notify_admin_on_feedback': True}
        
        if not settings.get('notify_admin_on_feedback', True):
            log_message("Admin notifications disabled in settings", "INFO")
            return
        
        subject = f"📝 New Feedback Received: {feedback['type'].upper()}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: auto; padding: 20px; background: #f8fafc; border-radius: 10px; }}
                .header {{ background: #6C63FF; color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center; }}
                .content {{ padding: 20px; background: white; }}
                .feedback-item {{ margin: 15px 0; padding: 15px; background: #f1f5f9; border-radius: 6px; }}
                .stars {{ color: #FFC107; font-size: 18px; }}
                .type-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
                .type-suggestion {{ background: #e0e7ff; color: #4f46e5; }}
                .type-bug {{ background: #fee2e2; color: #dc2626; }}
                .type-praise {{ background: #d1fae5; color: #059669; }}
                .type-general {{ background: #f3f4f6; color: #4b5563; }}
                .action-buttons {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📝 New Feedback Received</h1>
                    <p>Priority: {'🔴 High' if feedback['type'] == 'bug' else '🟡 Medium' if feedback['type'] == 'suggestion' else '🟢 Low'}</p>
                </div>
                <div class="content">
                    <div class="feedback-item">
                        <h3>{feedback['name']}</h3>
                        <p><strong>Type:</strong> <span class="type-badge type-{feedback['type']}">{feedback['type'].upper()}</span></p>
                        <p><strong>Rating:</strong> <span class="stars">{'★' * feedback['rating']}{'☆' * (5 - feedback['rating'])}</span> ({feedback['rating']}/5)</p>
                        <p><strong>Email:</strong> {feedback.get('email', 'No email')}</p>
                        <p><strong>Message:</strong></p>
                        <div style="background: #f8fafc; padding: 15px; border-radius: 6px; margin: 10px 0;">
                            {feedback['message'][:500] + ('...' if len(feedback['message']) > 500 else '')}
                        </div>
                        <p><strong>Time:</strong> {datetime.fromisoformat(feedback['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="action-buttons">
                        <p><strong>Quick Actions:</strong></p>
                        <a href="{url_for('feedback_viewer', _external=True)}" style="background: #6C63FF; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px;">
                            View in Feedback Dashboard
                        </a>
                        {f'<a href="mailto:{feedback["email"]}?subject=Re: Your EventFlow Feedback" style="background: #10b981; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px;">Reply to User</a>' if feedback.get('email') else ''}
                    </div>
                    
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280;">
                        <p>This is an automated notification from EventFlow Feedback System.</p>
                        <p>Feedback ID: {feedback['id']} | User ID: {feedback.get('user_id', 'N/A')}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send to admin email from settings or default
        admin_email = settings.get('admin_email', os.environ.get('ADMIN_EMAIL', MAIL_USERNAME))
        if admin_email:
            success, message = send_email_simple(admin_email, subject, html_content)
            if success:
                log_message(f"Feedback notification sent to {admin_email}", "INFO")
            else:
                log_message(f"Failed to send feedback notification: {message}", "ERROR")
                
    except Exception as e:
        log_message(f"Error sending feedback notification: {e}", "ERROR")

# ============================================================================
# FORM ACTIVITY CHECKING
# ============================================================================

def check_form_active_status(form_data):
    """Check if form is active based on schedule - FIXED VERSION"""
    if not form_data:
        return True, "Form is active"
    
    try:
        # FIX: Check if schedule exists and is not None
        schedule = form_data.get('schedule')
        if not schedule or schedule is None:
            return True, "Form is active"
        
        # FIX: Ensure schedule is a dictionary
        if not isinstance(schedule, dict):
            return True, "Form is active"
        
        start_datetime = schedule.get('start_datetime')
        end_datetime = schedule.get('end_datetime')
        
        now = datetime.now()
        
        # Check if before start time
        if start_datetime:
            try:
                start_time = None
                # Try ISO format with T
                try:
                    start_time = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
                except:
                    # Try space format
                    try:
                        start_time = datetime.strptime(start_datetime, '%Y-%m-%d %H:%M:%S')
                    except:
                        # Try without seconds
                        try:
                            start_time = datetime.strptime(start_datetime, '%Y-%m-%d %H:%M')
                        except:
                            # Try just date
                            try:
                                start_time = datetime.strptime(start_datetime, '%Y-%m-%d')
                            except:
                                print(f"   ❌ Could not parse start datetime: {start_datetime}")
                                start_time = None
                
                if start_time:
                    if now < start_time:
                        time_diff = start_time - now
                        hours = int(time_diff.total_seconds() // 3600)
                        minutes = int((time_diff.total_seconds() % 3600) // 60)
                        seconds = int(time_diff.total_seconds() % 60)
                        
                        if hours > 24:
                            days = hours // 24
                            hours = hours % 24
                            message = f"Form opens in {days}d {hours}h"
                        elif hours > 0:
                            message = f"Form opens in {hours}h {minutes}m"
                        else:
                            message = f"Form opens in {minutes}m {seconds}s"
                        
                        return False, message
            except Exception as e:
                print(f"   ❌ Error parsing start datetime: {e}")
        
        # Check if after end time
        if end_datetime:
            try:
                end_time = None
                # Try ISO format with T
                try:
                    end_time = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
                except:
                    # Try space format
                    try:
                        end_time = datetime.strptime(end_datetime, '%Y-%m-%d %H:%M:%S')
                    except:
                        # Try without seconds
                        try:
                            end_time = datetime.strptime(end_datetime, '%Y-%m-%d %H:%M')
                        except:
                            # Try just date
                            try:
                                end_time = datetime.strptime(end_datetime, '%Y-%m-%d')
                            except:
                                print(f"   ❌ Could not parse end datetime: {end_datetime}")
                                end_time = None
                
                if end_time:
                    if now > end_time:
                        return False, "Form has closed"
            except Exception as e:
                print(f"   ❌ Error parsing end datetime: {e}")
        
        # Form is active
        return True, "Form is active"
        
    except Exception as e:
        print(f"   ❌ Error in check_form_active_status: {e}")
        return True, "Form is active"

# ============================================================================
# CUSTOM JINJA2 FILTERS
# ============================================================================
@app.template_filter()
def slugify(s):
    """Convert string to URL-friendly slug"""
    if not s:
        return ""
    s = str(s).lower().strip()
    s = re.sub(r'\s+', '-', s)
    s = re.sub(r'[^\w\-]', '', s)
    s = re.sub(r'\-+', '-', s)
    return s

@app.template_filter()
def truncate(s, length=30):
    """Truncate string to specified length"""
    if not s:
        return ""
    if len(s) <= length:
        return s
    return s[:length] + "..."

@app.template_filter()
def format_date(date_string):
    """Format date string"""
    if not date_string:
        return ""
    
    try:
        if 'T' in date_string:
            dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        else:
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d/%m/%Y %H:%M:%S'):
                try:
                    dt = datetime.strptime(date_string, fmt)
                    break
                except ValueError:
                    continue
            else:
                return date_string
        
        return dt.strftime('%Y-%m-%d %H:%M')
    except Exception:
        return date_string

@app.template_filter()
def relative_time(timestamp):
    """Show relative time (e.g., '2 minutes ago')"""
    if not timestamp:
        return "just now"
    
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 0:
            if diff.days == 1:
                return "yesterday"
            elif diff.days < 7:
                return f"{diff.days} days ago"
            else:
                return dt.strftime('%b %d')
        elif diff.seconds < 60:
            return "just now"
        elif diff.seconds < 3600:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
    except:
        return timestamp

@app.template_filter()
def type_badge_color(feedback_type):
    """Get badge color for feedback type"""
    colors = {
        'suggestion': 'type-suggestion',
        'bug': 'type-bug', 
        'praise': 'type-praise',
        'general': 'type-general',
        'question': 'type-question'
    }
    return colors.get(feedback_type, 'type-general')

@app.template_filter()
def type_display_name(feedback_type):
    """Get display name for feedback type"""
    names = {
        'suggestion': 'Feature Idea',
        'bug': 'Bug Report',
        'praise': 'Praise',
        'general': 'General',
        'question': 'Question'
    }
    return names.get(feedback_type, feedback_type)

@app.template_filter()
def status_badge_color(status):
    """Get badge color for status"""
    colors = {
        'new': 'status-new',
        'read': 'status-read',
        'responded': 'status-responded',
        'closed': 'status-closed'
    }
    return colors.get(status, 'status-new')

@app.template_filter()
def status_display_name(status):
    """Get display name for status"""
    names = {
        'new': 'New',
        'read': 'Read',
        'responded': 'Responded',
        'closed': 'Closed'
    }
    return names.get(status, status)

@app.template_filter()
def basename(path):
    """Get filename from path"""
    if not path:
        return ""
    return os.path.basename(path)

@app.template_filter()
def dirname(path):
    """Get directory name from path"""
    if not path:
        return ""
    return os.path.dirname(path)

@app.template_filter()
def filesize(size_bytes):
    """Convert bytes to human readable format"""
    if not size_bytes:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

@app.template_filter()
def time_ago(timestamp):
    """Convert timestamp to relative time"""
    if not timestamp:
        return "just now"
    
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
        elif diff.days > 7:
            weeks = diff.days // 7
            return f"{weeks} week{'s' if weeks > 1 else ''} ago"
        elif diff.days > 0:
            if diff.days == 1:
                return "yesterday"
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "just now"
    except:
        return timestamp

# ============================================================================
# CSRF TOKEN FUNCTION
# ============================================================================

def generate_csrf_token():
    """Generate and return CSRF token for forms"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid.uuid4())
    return session['_csrf_token']

# Register as a global Jinja2 function
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ============================================================================
# CORE ROUTES
# ============================================================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Get real statistics
    stats = get_server_statistics()
    
    # Format for display
    display_stats = {
        'users': stats['users'],
        'events': stats['events'],
        'forms': stats['forms'],
        'registrations': stats['registrations']
    }
    
    return render_template('index.html', stats=display_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        if not identifier or not password:
            flash('Email/Mobile and password are required!', 'error')
            return redirect(url_for('login'))
        
        users = load_users()
        
        for user_id, user_data in users.items():
            email_match = user_data.get('email') == identifier
            mobile_match = user_data.get('mobile') == identifier
            
            if email_match or mobile_match:
                if user_data.get('password') == password:
                    session['user_id'] = user_id
                    session['username'] = user_data.get('username', 'User')
                    session['email'] = user_data.get('email', '')
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
        
        flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        
        print(f"\n" + "="*60)
        print("📝 SIGNUP REQUEST")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   Mobile: {mobile}")
        print("="*60 + "\n")
        
        if not all([username, email, mobile, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        
        # Check if email already exists
        users = load_users()
        for user_data in users.values():
            if user_data.get('email') == email:
                flash('Email already registered!', 'error')
                return redirect(url_for('signup'))
        
        # Store email in session
        session['verify_email'] = email
        session['pending_user'] = {
            'username': username,
            'email': email,
            'mobile': mobile,
            'password': password
        }
        
        # Generate OTP - SESSION BASED FIX
        try:
            # 1. Generate secure 6-digit OTP
            import secrets
            import time
            otp = str(secrets.randbelow(1000000)).zfill(6)
            
            # 2. Store OTP directly in the user's session (cookies)
            # This works even if file writing fails
            session['signup_otp'] = otp
            session['signup_otp_timestamp'] = time.time()
            
            print(f"✅ SESSION OTP Generated for {email}: {otp}")
            
            # 3. Send OTP email
            print(f"📧 Sending OTP email to {email}...")
            success, message = send_otp_email(email, otp)
            
            if success:
                flash(f'✅ Verification code sent to {email}!', 'success')
                flash('⏳ Code expires in 5 minutes', 'info')
                print(f"🎁 DEBUG OTP FOR {email}: {otp}")
                
                # Send welcome email immediately (even before verification)
                send_welcome_email_with_guidelines(email, username)
                
                return redirect(url_for('verify_email'))
            else:
                flash(f'❌ Failed to send email: {message}', 'error')
                session.pop('verify_email', None)
                session.pop('pending_user', None)
                # Clear OTP data on failure
                session.pop('signup_otp', None)
                session.pop('signup_otp_timestamp', None)
                return redirect(url_for('signup'))
                
        except Exception as e:
            import traceback
            print(f"❌ Error generating OTP: {str(e)}")
            print(f"📋 Traceback: {traceback.format_exc()}")
            flash(f'❌ Error generating OTP: {str(e)[:50]}', 'error')
            session.pop('verify_email', None)
            session.pop('pending_user', None)
            session.pop('signup_otp', None)
            session.pop('signup_otp_timestamp', None)
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

def send_otp_email(email: str, otp: str):
    """Send OTP email"""
    try:
        subject = "🔐 Your EventFlow Verification Code"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .otp-box {{ background: white; border: 2px dashed #4361ee; padding: 25px; text-align: center; margin: 30px 0; 
                           font-size: 32px; font-weight: bold; color: #4361ee; letter-spacing: 10px; border-radius: 10px; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .note {{ background: #fff3cd; padding: 15px; border-radius: 6px; margin: 20px 0; color: #856404; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Verify Your Email</h1>
                </div>
                <div style="padding: 30px;">
                    <p>Hello,</p>
                    
                    <p>You're signing up for EventFlow. Use this OTP to verify your email:</p>
                    
                    <div class="otp-box">
                        {otp}
                    </div>
                    
                    <div class="note">
                        <p><strong>⚠️ Important:</strong></p>
                        <ul>
                            <li>This OTP is valid for 5 minutes only</li>
                            <li>Don't share this code with anyone</li>
                            <li>If you didn't request this, please ignore this email</li>
                        </ul>
                    </div>
                    
                    <p>Enter this code on the verification page to complete your registration.</p>
                    
                    <div class="footer">
                        <p>EventFlow Registration System</p>
                        <p>© {datetime.now().year} | This is an automated email, please do not reply</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        success, message = send_email_simple(email, subject, html_content)
        
        if success:
            log_message(f"✅ OTP email sent to {email}", "SUCCESS")
        else:
            log_message(f"❌ Failed to send OTP email to {email}: {message}", "ERROR")
        
        return success, message
        
    except Exception as e:
        error_msg = f"OTP email error: {str(e)}"
        log_message(f"❌ OTP email exception: {error_msg}", "ERROR")
        return False, error_msg

@app.route('/test_otp_save')
def test_otp_save():
    """Test if OTP can be saved"""
    import json
    import os
    import time  # ADD THIS IMPORT
    
    test_email = "test@example.com"
    test_otp = "123456"
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Try to write directly
    test_file = 'data/test_write.json'
    try:
        # Test 1: Write directly
        with open(test_file, 'w') as f:
            json.dump({'test': 'data'}, f)
        
        # Test 2: Read back
        with open(test_file, 'r') as f:
            data = json.load(f)
        
        # Test 3: Write OTP data
        otp_data = {test_email: {'otp': test_otp, 'timestamp': time.time()}}
        otp_file = 'data/otp_store.json'
        with open(otp_file, 'w') as f:
            json.dump(otp_data, f, indent=4)
        
        # Test 4: Read OTP data back
        with open(otp_file, 'r') as f:
            read_data = json.load(f)
        
        return jsonify({
            'success': True,
            'direct_write': 'OK',
            'direct_read': data,
            'otp_write': 'OK' if os.path.exists(otp_file) else 'FAILED',
            'otp_read': read_data,
            'file_size': os.path.getsize(otp_file) if os.path.exists(otp_file) else 0,
            'permissions': oct(os.stat('data').st_mode)[-3:] if os.path.exists('data') else 'N/A'
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc(),
            'cwd': os.getcwd(),
            'data_dir': os.path.exists('data'),
            'can_write_to_data': os.access('data', os.W_OK) if os.path.exists('data') else False
        })
        
@app.route('/debug_otp_full')
def debug_otp_full():
    """Full OTP system debug"""
    import json
    import os
    
    try:
        # Test 1: Check imports
        from otp import generate_and_store_otp, verify_otp, _load_otp_store
        
        # Test 2: Check data directory
        os.makedirs('data', exist_ok=True)
        
        # Test 3: Clean any existing test data
        store = _load_otp_store()
        test_email = "debug_test@example.com"
        if test_email in store:
            del store[test_email]
            with open('data/otp_store.json', 'w') as f:
                json.dump(store, f, indent=4)
        
        # Test 4: Generate OTP
        print(f"\n🔧 Generating OTP for {test_email}...")
        otp = generate_and_store_otp(test_email)
        
        if not otp:
            return jsonify({
                'success': False,
                'step': 'generate',
                'error': 'OTP generation returned None'
            })
        
        # Test 5: Verify file was created
        otp_file = 'data/otp_store.json'
        if not os.path.exists(otp_file):
            return jsonify({
                'success': False,
                'step': 'file_creation',
                'error': 'OTP file not created'
            })
        
        # Test 6: Read file to verify content
        with open(otp_file, 'r') as f:
            file_content = f.read().strip()
            if not file_content:
                return jsonify({
                    'success': False,
                    'step': 'file_content',
                    'error': 'OTP file is empty'
                })
            
            data = json.loads(file_content)
            if test_email not in data:
                return jsonify({
                    'success': False,
                    'step': 'email_in_file',
                    'error': f'Email not found in OTP file. Keys: {list(data.keys())}'
                })
        
        # Test 7: Verify OTP
        print(f"\n🔧 Verifying OTP {otp}...")
        success, message = verify_otp(test_email, otp)
        
        return jsonify({
            'success': success,
            'otp_generated': otp,
            'message': message,
            'otp_file_exists': os.path.exists(otp_file),
            'otp_file_size': os.path.getsize(otp_file),
            'otp_file_content': data if len(data) < 5 else f"{len(data)} entries",
            'data_dir_writable': os.access('data', os.W_OK),
            'full_path': os.path.abspath(otp_file)
        })
        
    except ImportError as e:
        return jsonify({
            'success': False,
            'error': f'Import error: {str(e)}',
            'cwd': os.getcwd(),
            'files_in_cwd': os.listdir('.')
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })        
        
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Verify OTP for email confirmation"""
    print(f"\n" + "="*60)
    print("🔐 VERIFY EMAIL ROUTE")
    print(f"   Session verify_email: {session.get('verify_email')}")
    print(f"   Session pending_user: {session.get('pending_user')}")
    print(f"   Session signup_otp: {session.get('signup_otp')}")
    print("="*60 + "\n")
    
    email = session.get('verify_email')
    pending_user = session.get('pending_user')
    
    if not email and pending_user:
        email = pending_user.get('email')
        session['verify_email'] = email
        print(f"📝 Using email from pending_user: {email}")
    
    if not email:
        print(f"❌ No email found in session")
        flash('⚠️ Session expired. Please sign up again.', 'warning')
        return redirect(url_for('signup'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        print(f"📝 User OTP input: '{user_otp}'")
        
        if not user_otp or len(user_otp) != 6:
            flash('Please enter a valid 6-digit code.', 'error')
            return render_template('verify_email.html', email=email)
        
        # Verify OTP - SESSION BASED FIX
        try:
            import time
            
            # 1. Retrieve OTP from session
            stored_otp = session.get('signup_otp')
            timestamp = session.get('signup_otp_timestamp')
            
            print(f"🔍 Verify Request - Input: {user_otp} | Stored: {stored_otp}")
            
            is_valid = False
            message = ""

            if not stored_otp:
                message = "Session expired or invalid. Please try signing up again."
            elif not timestamp:
                message = "Invalid OTP session. Please request a new code."
            elif time.time() - float(timestamp) > 300:  # 5 minutes expiration
                message = "OTP has expired. Please request a new one."
            elif user_otp.strip() != stored_otp:
                message = "Invalid code. Please try again."
            else:
                is_valid = True
                message = "OTP verified successfully"
                # Clear OTP from session to prevent reuse
                session.pop('signup_otp', None)
                session.pop('signup_otp_timestamp', None)

            print(f"📋 Verification result: {is_valid} - {message}")
            
            if is_valid:
                # Get user data
                if pending_user:
                    username = pending_user.get('username')
                    mobile = pending_user.get('mobile')
                    password = pending_user.get('password')
                else:
                    username = email.split('@')[0]
                    mobile = 'N/A'
                    password = 'to_be_changed'
                
                print(f"✅ Creating user account for {email}")
                
                # Create user account
                users = load_users()
                user_id = str(uuid.uuid4())
                users[user_id] = {
                    'username': username,
                    'email': email,
                    'mobile': mobile,
                    'password': password,
                    'created_at': datetime.now().isoformat(),
                    'email_verified': True,
                    'guidelines_accepted': True,
                    'welcome_email_sent': True
                }
                
                save_users(users)
                
                # Clear session data
                session.pop('verify_email', None)
                session.pop('pending_user', None)
                
                # Log user in
                session['user_id'] = user_id
                session['username'] = username
                session['email'] = email
                
                # Send account activation confirmation email
                send_account_activated_email(email, username)
                
                flash('🎉 Email verified! Account created successfully.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(f'❌ {message}', 'error')
                return render_template('verify_email.html', email=email)
                
        except Exception as e:
            import traceback
            print(f"❌ Error in verify_email: {str(e)}")
            print(f"📋 Traceback: {traceback.format_exc()}")
            flash(f'Verification error: {str(e)[:50]}', 'error')
            return render_template('verify_email.html', email=email)
    
    return render_template('verify_email.html', email=email)

@app.route('/debug_permissions')
def debug_permissions():
    """Debug file permissions"""
    result = {
        'data_dir_exists': os.path.exists('data'),
        'data_dir_writable': os.access('data', os.W_OK) if os.path.exists('data') else False,
        'current_dir': os.getcwd(),
        'files_in_data_dir': []
    }
    
    if os.path.exists('data'):
        result['files_in_data_dir'] = os.listdir('data')
        
        # Try to create OTP file
        try:
            test_file = 'data/test_permissions.txt'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            result['can_write_to_data'] = True
        except Exception as e:
            result['can_write_to_data'] = False
            result['write_error'] = str(e)
    
    return jsonify(result)

@app.route('/check_otp_system')
def check_otp_system():
    """Check if OTP system is working"""
    try:
        from otp import generate_and_store_otp, verify_otp, _load_otp_store
        
        test_email = "test@example.com"
        
        # Clean up any existing test OTP
        store = _load_otp_store()
        if test_email in store:
            store.pop(test_email)
            import json
            with open('data/otp_store.json', 'w') as f:
                json.dump(store, f, indent=4)
        
        # Test OTP generation
        print(f"\n🔧 Testing OTP generation for {test_email}")
        otp = generate_and_store_otp(test_email)
        
        if not otp:
            return jsonify({
                'success': False,
                'error': 'Failed to generate OTP'
            })
        
        # Test OTP verification
        print(f"\n🔧 Testing OTP verification")
        is_valid, message = verify_otp(test_email, otp)
        
        return jsonify({
            'success': is_valid,
            'otp_generated': otp,
            'verification_result': message,
            'otp_file_exists': os.path.exists('data/otp_store.json'),
            'otp_file_size': os.path.getsize('data/otp_store.json') if os.path.exists('data/otp_store.json') else 0,
            'data_dir_writable': os.access('data', os.W_OK) if os.path.exists('data') else False
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })
    
@app.route('/debug_otp_status')
def debug_otp_status():
    """Debug OTP system status"""
    otp_file = 'data/otp_store.json'
    result = {
        'otp_file_exists': os.path.exists(otp_file),
        'otp_file_path': os.path.abspath(otp_file) if os.path.exists(otp_file) else None,
        'data_dir_exists': os.path.exists('data'),
        'current_time': time.time(),
        'session_email': session.get('verify_email'),
        'session_pending': bool(session.get('pending_user'))
    }
    
    if os.path.exists(otp_file):
        try:
            with open(otp_file, 'r') as f:
                otp_data = json.load(f)
                result['otp_data'] = otp_data
                result['otp_count'] = len(otp_data)
        except Exception as e:
            result['otp_read_error'] = str(e)
    
    return jsonify(result)

@app.route('/resend-otp')
def resend_otp():
    """Resend OTP to email from session"""
    email = session.get('verify_email')
    pending_user = session.get('pending_user')
    
    if not email and pending_user:
        email = pending_user.get('email')
        session['verify_email'] = email
    
    if not email:
        flash('No pending verification found. Please sign up again.', 'error')
        return redirect(url_for('signup'))
    
    # Generate new OTP - SESSION BASED FIX
    try:
        import secrets
        import time
        
        otp = str(secrets.randbelow(1000000)).zfill(6)
        
        # Update session
        session['signup_otp'] = otp
        session['signup_otp_timestamp'] = time.time()
        
        success, message = send_otp_email(email, otp)
        
        if success:
            flash('✅ New verification code sent! Check your email.', 'success')
            print(f"🎁 DEBUG RESEND OTP FOR {email}: {otp}")
        else:
            flash(f'❌ Failed to resend code: {message}', 'error')
        
        return redirect(url_for('verify_email'))
        
    except Exception as e:
        flash(f'❌ Error resending OTP: {str(e)[:50]}', 'error')
        return redirect(url_for('verify_email'))
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - shows different content for admin vs regular users"""
    try:
        is_admin = session.get('user_id') == 'admin'
        
        if is_admin:
            # ==================== ADMIN DASHBOARD ====================
            stats = get_server_statistics()
            
            # Get recent feedback (last 5)
            feedback_data = load_feedback()
            recent_feedback = sorted(feedback_data, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
            
            # Get form reports
            reports = load_form_reports()
            blocked_forms = load_blocked_forms()
            
            # Calculate admin stats
            admin_stats = {
                'total_users': stats['users'],
                'total_feedback': len(feedback_data),
                'total_events': stats['events'],
                'total_forms': stats['forms'],
                'total_submissions': stats['registrations'],
                'pending_feedback': sum(1 for fb in feedback_data if fb.get('status') == 'new'),
                'unread_feedback': sum(1 for fb in feedback_data if fb.get('status') == 'new'),
                'new_users_today': 0,
                'new_events_today': 0,
                'new_forms_today': 0,
                'active_reports': len(reports),
                'blocked_forms': len(blocked_forms),
                'system_health': 'good'
            }
            
            # Get today's activity
            today = datetime.now().date()
            
            # Count new users today
            users = load_users()
            today_users = 0
            for user_data in users.values():
                created_date = datetime.fromisoformat(user_data.get('created_at', '2000-01-01')).date()
                if created_date == today:
                    today_users += 1
            admin_stats['new_users_today'] = today_users
            
            # Count new events today
            today_events = 0
            today_forms = 0
            for filename in os.listdir('data/events'):
                if filename.endswith('.json'):
                    try:
                        with open(f'data/events/{filename}', 'r') as f:
                            event = json.load(f)
                            created_date = datetime.fromisoformat(event.get('created_at', '2000-01-01')).date()
                            if created_date == today:
                                today_events += 1
                                today_forms += len(event.get('forms', []))
                    except:
                        continue
            admin_stats['new_events_today'] = today_events
            admin_stats['new_forms_today'] = today_forms
            
            # Get admin's events
            admin_events = []
            event_count = 0
            form_count = 0
            for filename in os.listdir('data/events'):
                if filename.endswith('.json'):
                    try:
                        with open(f'data/events/{filename}', 'r') as f:
                            event = json.load(f)
                            if event.get('creator_id') == session['user_id']:  # Admin's events
                                admin_events.append(event)
                                event_count += 1
                                form_count += len(event.get('forms', []))
                    except:
                        continue
            
            # Recent activity for admin
            recent_activity = []
            
            # Get recent user signups (last 5)
            user_list = list(users.items())[-5:]
            for user_id, user_data in user_list:
                if user_id != 'admin':  # Skip admin from activity
                    recent_activity.append({
                        'type': 'user_signup',
                        'user': user_data.get('username', 'User'),
                        'time': user_data.get('created_at', ''),
                        'description': 'New user registration',
                        'icon': 'bi-person-plus',
                        'color': 'text-success'
                    })
            
            # Get recent events (last 3)
            event_files = sorted([f for f in os.listdir('data/events') if f.endswith('.json')], 
                               key=lambda x: os.path.getmtime(f'data/events/{x}'),
                               reverse=True)[:3]
            
            for event_file in event_files:
                try:
                    with open(f'data/events/{event_file}', 'r') as f:
                        event = json.load(f)
                        recent_activity.append({
                            'type': 'event_created',
                            'user': event.get('creator_id', 'Unknown'),
                            'time': event.get('created_at', ''),
                            'description': f'Created event: {event.get("name", "Unknown")}',
                            'icon': 'bi-calendar-plus',
                            'color': 'text-primary'
                        })
                except:
                    continue
            
            # Get recent feedback activity
            for fb in recent_feedback:
                recent_activity.append({
                    'type': 'feedback_received',
                    'user': fb.get('name', 'Anonymous'),
                    'time': fb.get('timestamp', ''),
                    'description': f'New {fb.get("type", "feedback")}: {fb.get("message", "")[:50]}...',
                    'icon': 'bi-chat-left-text',
                    'color': 'text-warning' if fb.get('type') == 'bug' else 'text-info'
                })
            
            # Sort activity by time
            recent_activity.sort(key=lambda x: x.get('time', ''), reverse=True)
            recent_activity = recent_activity[:8]  # Limit to 8 items
            
            # Check email configuration status
            email_config_status = "✅ Configured" if MAIL_USERNAME and MAIL_PASSWORD else "❌ Not Configured"
            
            # Get growth statistics
            growth_stats = calculate_growth_stats()
            
            return render_template('admin_dashboard.html',
                                 stats=admin_stats,
                                 recent_feedback=recent_feedback,
                                 recent_activity=recent_activity,
                                 admin_events=admin_events,
                                 event_count=event_count,
                                 form_count=form_count,
                                 is_admin=True,
                                 email_config_status=email_config_status,
                                 growth_stats=growth_stats,
                                 user_id=session['user_id'],
                                 username=session.get('username'),
                                 email=session.get('email'))
        
        else:
            # ==================== REGULAR USER DASHBOARD ====================
            # Load user data
            users = load_users()
            user_data = users.get(session['user_id'], {})
            
            # SKIP guidelines check entirely
            needs_guidelines_review = False
            guidelines_accepted = True  # Assume accepted
            
            # Get user statistics
            event_count = get_user_events_count(session['user_id'])
            form_count = get_user_forms_count(session['user_id'])
            
            # Load user events with detailed information
            user_events = []
            total_registrations = 0
            active_forms_count = 0
            
            for filename in os.listdir('data/events'):
                if filename.endswith('.json'):
                    try:
                        with open(f'data/events/{filename}', 'r') as f:
                            event = json.load(f)
                            if event.get('creator_id') == session['user_id']:
                                # Add form count and registration count to each event
                                event_forms = event.get('forms', [])
                                event['form_count'] = len(event_forms)
                                
                                # Count registrations for this event
                                event_registrations = 0
                                for form in event_forms:
                                    form_id = form.get('id')
                                    csv_path = f'data/events/{event["id"]}/{form_id}.csv'
                                    if os.path.exists(csv_path):
                                        try:
                                            with open(csv_path, 'r', encoding='utf-8') as csv_file:
                                                reader = csv.reader(csv_file)
                                                event_registrations += max(0, len(list(reader)) - 1)
                                        except:
                                            pass
                                    
                                    # Check if form is active
                                    is_active, _ = check_form_active_status(form)
                                    if is_active:
                                        active_forms_count += 1
                                
                                event['registration_count'] = event_registrations
                                total_registrations += event_registrations
                                
                                user_events.append(event)
                    except Exception as e:
                        log_message(f"Error loading event {filename}: {e}", "ERROR")
                        continue
            
            # Sort events by creation date (newest first)
            user_events.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            # Get recent activity
            recent_activity = []
            
            # Add recent event creations
            for event in user_events[:3]:  # Last 3 events
                recent_activity.append({
                    'type': 'event_created',
                    'title': event.get('name', 'Unknown Event'),
                    'time': event.get('created_at', ''),
                    'icon': 'bi-calendar-plus',
                    'color': 'text-primary'
                })
            
            # Add recent form submissions (from the last 24 hours)
            twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
            
            for event in user_events:
                event_id = event.get('id')
                for form in event.get('forms', []):
                    form_id = form.get('id')
                    csv_path = f'data/events/{event_id}/{form_id}.csv'
                    
                    if os.path.exists(csv_path):
                        try:
                            with open(csv_path, 'r', encoding='utf-8') as csv_file:
                                reader = csv.reader(csv_file)
                                rows = list(reader)
                                
                                if len(rows) > 1:  # Has submissions
                                    # Check last submission time
                                    last_row = rows[-1]
                                    if len(last_row) > 0:
                                        try:
                                            submission_time = datetime.strptime(last_row[0], '%Y-%m-%d %H:%M:%S')
                                            if submission_time > twenty_four_hours_ago:
                                                recent_activity.append({
                                                    'type': 'form_submission',
                                                    'title': f"New submission: {form.get('title', 'Unknown Form')}",
                                                    'time': submission_time.isoformat(),
                                                    'icon': 'bi-check-circle',
                                                    'color': 'text-success'
                                                })
                                        except:
                                            pass
                        except:
                            continue
            
            # Sort activity by time
            recent_activity.sort(key=lambda x: x.get('time', ''), reverse=True)
            recent_activity = recent_activity[:5]  # Limit to 5 items
            
            # Calculate pending items (forms with schedule ending soon)
            pending_items = 0
            ending_soon_forms = []
            
            for event in user_events:
                for form in event.get('forms', []):
                    schedule = form.get('schedule', {})
                    if schedule and schedule.get('end_datetime'):
                        try:
                            end_time = datetime.fromisoformat(
                                schedule['end_datetime'].replace('T', ' ') if 'T' in schedule['end_datetime'] 
                                else schedule['end_datetime']
                            )
                            time_left = end_time - datetime.now()
                            
                            # If form ends in next 24 hours
                            if timedelta(0) < time_left < timedelta(hours=24):
                                pending_items += 1
                                ending_soon_forms.append({
                                    'form_title': form.get('title', 'Unknown'),
                                    'event_name': event.get('name', 'Unknown'),
                                    'ends_at': end_time.strftime('%Y-%m-%d %H:%M'),
                                    'time_left': str(time_left).split('.')[0]
                                })
                        except:
                            continue
            
            # Regular user stats
            user_stats = {
                'total_events': event_count,
                'total_forms': form_count,
                'total_registrations': total_registrations,
                'pending_items': pending_items,
                'active_forms': active_forms_count,
                'inactive_forms': form_count - active_forms_count,
                'guidelines_accepted': guidelines_accepted,
                'account_age': calculate_account_age(user_data.get('created_at')),
                'storage_used': calculate_user_storage(session['user_id'])
            }
            
            # Get user's recent feedback submissions
            user_feedback = []
            feedback_data = load_feedback()
            for fb in feedback_data:
                if fb.get('user_id') == session['user_id']:
                    user_feedback.append(fb)
            
            user_stats['feedback_submitted'] = len(user_feedback)
            
            # Check if welcome email was sent
            welcome_email_sent = user_data.get('welcome_email_sent', False)
            
            # Get user's most recent forms for quick access
            recent_forms = []
            for event in user_events[:2]:  # Last 2 events
                for form in event.get('forms', []):
                    recent_forms.append({
                        'title': form.get('title', 'Unknown'),
                        'event_name': event.get('name', 'Unknown'),
                        'event_id': event.get('id'),
                        'form_id': form.get('id'),
                        'created_at': form.get('created_at', event.get('created_at')),
                        'is_active': check_form_active_status(form)[0]
                    })
            
            # Limit to 3 recent forms
            recent_forms = recent_forms[:3]
            
            # Calculate completion percentage (for fun)
            completion_percentage = min(100, int(
                (event_count * 20 + form_count * 10 + min(total_registrations, 100) * 0.5)
            ))
            
            return render_template('dashboard.html',
                                 events=user_events[:5],  # Only show last 5 events
                                 event_count=event_count,
                                 form_count=form_count,
                                 stats=user_stats,
                                 is_admin=False,
                                 needs_guidelines_review=False,  # Always false
                                 guidelines_accepted=True,  # Always true
                                 recent_activity=recent_activity,
                                 recent_forms=recent_forms,
                                 welcome_email_sent=welcome_email_sent,
                                 ending_soon_forms=ending_soon_forms,
                                 completion_percentage=completion_percentage,
                                 user_id=session['user_id'],
                                 username=session.get('username'),
                                 email=session.get('email'),
                                 join_date=user_data.get('created_at', ''),
                                 user_feedback=user_feedback[:3])  # Last 3 feedback items
        
    except Exception as e:
        log_message(f"Error loading dashboard: {e}", "ERROR")
        flash(f'Error loading dashboard: {str(e)[:100]}', 'error')
        return redirect(url_for('index'))
@app.route('/accept_guidelines', methods=['POST'])
def accept_guidelines():
    """Accept guidelines - SIMPLE WORKING VERSION"""
    print("=== ACCEPT GUIDELINES ROUTE CALLED ===")
    
    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({
            'success': False,
            'error': 'Not logged in'
        }), 401
    
    user_id = session['user_id']
    
    try:
        # Load users
        with open('data/users.json', 'r') as f:
            users = json.load(f)
        
        # Update user
        if user_id in users:
            users[user_id]['guidelines_accepted'] = True
            
            # Save users
            with open('data/users.json', 'w') as f:
                json.dump(users, f, indent=4)
            
            print(f"User {user_id} accepted guidelines")
            
            return jsonify({
                'success': True,
                'message': 'Guidelines accepted!',
                'redirect': url_for('dashboard')
            })
        else:
            return jsonify({
                'success': False,
                'error': 'User not found'
            })
            
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/debug_user/<user_id>')
def debug_user(user_id):
    """Debug a specific user's data"""
    users = load_users()
    user_data = users.get(user_id)
    
    if user_data:
        return jsonify({
            'success': True,
            'user_id': user_id,
            'guidelines_accepted': user_data.get('guidelines_accepted', 'NOT SET'),
            'first_login': user_data.get('first_login', 'NOT SET'),
            'email': user_data.get('email'),
            'username': user_data.get('username'),
            'created_at': user_data.get('created_at')
        })
    else:
        return jsonify({'success': False, 'error': 'User not found'})

@app.route('/accept_guidelines_get')
@login_required
def accept_guidelines_get():
    """GET version for testing"""
    user_id = session['user_id']
    
    with open('data/users.json', 'r') as f:
        users = json.load(f)
    
    if user_id in users:
        users[user_id]['guidelines_accepted'] = True
        
        with open('data/users.json', 'w') as f:
            json.dump(users, f, indent=4)
        
        flash('Guidelines accepted!', 'success')
    
    return redirect(url_for('dashboard'))


@app.route('/create_event', methods=['GET', 'POST'])
@login_required 
def create_event():
    """Create new event"""
    
    if request.method == 'GET':
        return render_template('create_event.html')
    
    # Get form data
    event_name = request.form.get('event_name')
    description = request.form.get('description')
    category = request.form.get('category', 'other')
    event_type = request.form.get('event_type', 'physical')
    notes = request.form.get('notes', '')
    
    if not event_name or not description:
        flash('Event name and description are required!', 'error')
        return redirect(url_for('create_event'))
    
    event_id = str(uuid.uuid4())
    event_data = {
        'id': event_id,
        'name': event_name,
        'description': description,
        'category': category,
        'type': event_type,
        'notes': notes,
        'creator_id': session['user_id'],
        'created_at': datetime.now().isoformat(),
        'forms': []
    }
    
    try:
        save_event(event_data)
        
        # Create directories
        os.makedirs(f'data/events/{event_id}', exist_ok=True)
        os.makedirs(f'static/uploads/events/{event_id}', exist_ok=True)
        
        flash('Event created successfully!', 'success')
        return redirect(url_for('create_form', event_id=event_id))
        
    except Exception as e:
        flash(f'Error creating event: {str(e)}', 'error')
        return redirect(url_for('create_event'))

# ============================================================================
# TEST ROUTES FOR DEBUGGING
# ============================================================================

@app.route('/simple_test')
def simple_test():
    """Simple test route that always returns JSON"""
    response = jsonify({
        'test': 'success',
        'message': 'This is JSON',
        'timestamp': datetime.now().isoformat(),
        'route': '/simple_test',
        'method': request.method
    })
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/create_form/<event_id>', methods=['GET', 'POST'])
@login_required
def create_form(event_id):
    """Create registration form for an event with IP tracking"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Event not found or unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        form_title = request.form.get('form_title', 'Registration Form')
        form_description = request.form.get('form_description', '')
        questions = []
        
        # Get schedule data
        enable_schedule = 'enable_schedule' in request.form
        schedule = {}
        
        if enable_schedule:
            start_datetime = request.form.get('start_datetime')
            end_datetime = request.form.get('end_datetime')
            
            notify_on_end = 'notify_on_end' in request.form
            
            # Validate schedule if provided
            if start_datetime or end_datetime:
                schedule = {
                    'enabled': True,
                    'start_datetime': start_datetime,
                    'end_datetime': end_datetime,
                    'notify_on_end': notify_on_end,
                    'created_at': datetime.now().isoformat(),
                    'notification_sent': False
                }
                
                log_message(f"📝 Form '{form_title}' created with notify_on_end = {notify_on_end}", "INFO")
                
                # If notify_on_end is enabled and end_datetime exists, schedule notification
                if notify_on_end and end_datetime:
                    user_email = session.get('email')
                    username = session.get('username', 'User')
                    
                    schedule_form_notification(
                        event_id=event_id,
                        form_id=None,
                        form_title=form_title,
                        end_datetime_str=end_datetime,
                        event_name=event['name'],
                        user_id=session['user_id'],
                        user_email=user_email
                    )
        
        # Process questions
        i = 0
        
        while f'question_{i}' in request.form:
            question_text = request.form.get(f'question_{i}')
            question_type = request.form.get(f'type_{i}', 'text')
            
            question = {
                'id': i,
                'text': question_text,
                'type': question_type,
                'required': request.form.get(f'required_{i}', 'off') == 'on'
            }
            
            if question_type in ['radio', 'checkbox', 'dropdown']:
                options = request.form.get(f'options_{i}', '').split(',')
                question['options'] = [opt.strip() for opt in options if opt.strip()]
            
            # Handle file upload specific settings
            if question_type == 'file':
                # CRITICAL: Use getlist() for checkboxes
                file_types = request.form.getlist(f'file_types_{i}[]')
                
                # Get max size with validation
                file_max_size = request.form.get(f'file_max_size_{i}', '16')
                if not file_max_size or not file_max_size.isdigit():
                    file_max_size = '16'
                
                # Get multiple files setting
                file_multiple = request.form.get(f'file_multiple_{i}', 'off') == 'on'
                
                # Debug output
                print(f"DEBUG EDIT: Saving file settings for question {i}:")
                print(f"  File types: {file_types}")
                print(f"  Max size: {file_max_size} MB")
                print(f"  Multiple: {file_multiple}")
                
                question['file_settings'] = {
                    'allowed_types': file_types,
                    'max_size_mb': int(file_max_size),
                    'multiple': file_multiple
                }
            
            questions.append(question)
            i += 1
        
        form_id = str(uuid.uuid4())
        form_data = {
            'id': form_id,
            'title': form_title,
            'description': form_description,
            'event_id': event_id,
            'questions': questions,
            'created_at': datetime.now().isoformat(),
            'schedule': schedule if schedule else None
        }
        
        event['forms'].append(form_data)
        save_event(event)
        
        # Update notification with form_id if we scheduled one
        if enable_schedule and schedule.get('notify_on_end') and schedule.get('end_datetime'):
            notification_dir = 'data/form_notifications'
            if os.path.exists(notification_dir):
                for filename in os.listdir(notification_dir):
                    if filename.endswith('.json'):
                        try:
                            with open(os.path.join(notification_dir, filename), 'r') as f:
                                notification = json.load(f)
                            
                            if notification.get('event_id') == event_id and notification.get('form_id') is None:
                                notification['form_id'] = form_id
                                notification['form_title'] = form_title
                                
                                with open(os.path.join(notification_dir, filename), 'w') as f:
                                    json.dump(notification, f, indent=2)
                                break
                        except:
                            continue
        
        # Create CSV for responses with IP Address header
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            headers = ['Timestamp', 'Response ID', 'Attendee IP']  # Changed to Attendee IP
            for q in questions:
                headers.append(q['text'])
            writer.writerow(headers)
        
        # Create upload directory for this form
        form_upload_dir = f'static/uploads/events/{event_id}/{form_id}'
        os.makedirs(form_upload_dir, exist_ok=True)
        
        flash('Form created successfully!', 'success')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    return render_template('create_form.html', event=event)

def check_form_blocked(form_id):
    """Check if form is blocked"""
    blocked_forms = load_blocked_forms()
    form_info = blocked_forms.get(form_id)
    
    if form_info:
        # Check if block is still valid (default 7 days)
        blocked_time = datetime.fromisoformat(form_info.get('blocked_at', datetime.now().isoformat()))
        block_duration = form_info.get('block_duration', 7)  # days
        
        # Calculate if block has expired
        if (datetime.now() - blocked_time).days >= block_duration:
            # Unblock the form
            blocked_forms.pop(form_id)
            save_blocked_forms(blocked_forms)
            log_message(f"Form {form_id} automatically unblocked after {block_duration} days", "MODERATION")
            return False, None, None
        
        return True, form_info.get('reason'), form_info.get('blocked_at')
    
    return False, None, None
                             
# ============================================================================
# ADDITIONAL ADMIN ROUTES
# ============================================================================

# Add these routes around line 1500-2000 range, near other admin routes

@app.route('/admin/bulk_delete_feedback', methods=['POST'])
@login_required
@admin_required
def bulk_delete_feedback():
    """Bulk delete feedback items"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        feedback_ids = data.get('feedback_ids', [])
        reason = data.get('reason', '')
        
        if not feedback_ids:
            return jsonify({'success': False, 'error': 'No feedback IDs provided'})
        
        feedback_data = load_feedback()
        original_count = len(feedback_data)
        
        # Filter out feedback to delete
        new_feedback_data = [fb for fb in feedback_data if fb['id'] not in feedback_ids]
        
        # Save updated feedback
        if save_feedback(new_feedback_data):
            deleted_count = original_count - len(new_feedback_data)
            
            # Log the bulk deletion
            log_message(f"Bulk deleted {deleted_count} feedback items. Reason: {reason}", "ADMIN")
            
            return jsonify({
                'success': True,
                'deleted_count': deleted_count,
                'message': f'Successfully deleted {deleted_count} feedback items'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback data'})
            
    except Exception as e:
        log_message(f"Error in bulk delete feedback: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# Add this route to the feedback management section
@app.route('/admin/clear_all_feedback', methods=['POST'])
@login_required
@admin_required
def admin_clear_all_feedback():
    """Clear all feedback"""
    try:
        feedback_file = 'data/feedback.json'
        
        # Create empty feedback list
        empty_feedback = []
        
        with open(feedback_file, 'w') as f:
            json.dump(empty_feedback, f, indent=4)
        
        log_message(f"All feedback cleared by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'All feedback cleared'})
        
    except Exception as e:
        log_message(f"Error clearing feedback: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/clear_cache', methods=['POST'])
@login_required
@admin_required
def admin_clear_cache():
    """Clear system cache"""
    try:
        # Clear session data (except admin session)
        keys_to_keep = ['user_id', 'username', 'email']
        session_keys = list(session.keys())
        for key in session_keys:
            if key not in keys_to_keep:
                session.pop(key, None)
        
        # Clear any file-based cache
        cache_dir = 'cache'
        if os.path.exists(cache_dir):
            for file in os.listdir(cache_dir):
                try:
                    os.remove(os.path.join(cache_dir, file))
                except:
                    pass
        
        log_message(f"System cache cleared by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Cache cleared successfully'})
        
    except Exception as e:
        log_message(f"Error clearing cache: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/optimize_database', methods=['POST'])
@login_required
@admin_required
def admin_optimize_database():
    """Optimize database files"""
    try:
        optimized_files = []
        
        # Optimize users.json
        users_file = 'data/users.json'
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                users = json.load(f)
            with open(users_file, 'w') as f:
                json.dump(users, f, indent=2)
            optimized_files.append('users.json')
        
        # Optimize feedback.json
        feedback_file = 'data/feedback.json'
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                feedback = json.load(f)
            with open(feedback_file, 'w') as f:
                json.dump(feedback, f, indent=2)
            optimized_files.append('feedback.json')
        
        # Optimize event files
        event_files = [f for f in os.listdir('data/events') if f.endswith('.json')]
        for event_file in event_files:
            try:
                with open(f'data/events/{event_file}', 'r') as f:
                    event = json.load(f)
                with open(f'data/events/{event_file}', 'w') as f:
                    json.dump(event, f, indent=2)
                optimized_files.append(f'events/{event_file}')
            except:
                continue
        
        log_message(f"Database optimized by admin. Files: {len(optimized_files)}", "ADMIN")
        return jsonify({
            'success': True, 
            'message': f'Optimized {len(optimized_files)} database files',
            'files': optimized_files
        })
        
    except Exception as e:
        log_message(f"Error optimizing database: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/system_diagnostics')
@login_required
@admin_required
def admin_system_diagnostics():
    """Run system diagnostics"""
    try:
        diagnostics = {
            'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'uptime': '24h 15m',  # This would be calculated in a real system
            'memory_usage': '45%',
            'cpu_load': 'Medium',
            'database_status': 'connected',
            'email_service': 'running',
            'storage_usage': '125 MB / 1 GB',
            'active_connections': 5,
            'recent_errors': [],
            'recommendations': [
                'Consider enabling automatic backups',
                'Review user activity logs weekly',
                'Update system dependencies'
            ]
        }
        
        return jsonify({'success': True, 'diagnostics': diagnostics})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/check_maintenance')
@login_required
@admin_required
def admin_check_maintenance():
    """Check maintenance mode status"""
    try:
        settings_file = 'data/settings.json'
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
            maintenance_mode = settings.get('maintenance_mode') == 'enabled'
            message = settings.get('maintenance_message', 'System is under maintenance')
        else:
            maintenance_mode = False
            message = ''
        
        return jsonify({
            'success': True,
            'maintenance_mode': maintenance_mode,
            'message': message
        })
    except:
        return jsonify({
            'success': True,
            'maintenance_mode': False,
            'message': ''
        })

@app.route('/admin/enable_maintenance', methods=['POST'])
@login_required
@admin_required
def admin_enable_maintenance():
    """Enable maintenance mode"""
    try:
        data = request.json
        message = data.get('message', 'System is currently under maintenance')
        duration = data.get('duration', 60)
        allow_admin = data.get('allow_admin', True)
        
        settings_file = 'data/settings.json'
        settings = {}
        
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        
        settings['maintenance_mode'] = 'enabled'
        settings['maintenance_message'] = message
        settings['maintenance_duration'] = duration
        settings['maintenance_allow_admin'] = allow_admin
        settings['maintenance_started'] = datetime.now().isoformat()
        
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=4)
        
        log_message(f"Maintenance mode enabled by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Maintenance mode enabled'})
        
    except Exception as e:
        log_message(f"Error enabling maintenance mode: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/disable_maintenance', methods=['POST'])
@login_required
@admin_required
def admin_disable_maintenance():
    """Disable maintenance mode"""
    try:
        settings_file = 'data/settings.json'
        settings = {}
        
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        
        settings['maintenance_mode'] = 'disabled'
        settings.pop('maintenance_message', None)
        settings.pop('maintenance_duration', None)
        settings.pop('maintenance_started', None)
        
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=4)
        
        log_message(f"Maintenance mode disabled by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Maintenance mode disabled'})
        
    except Exception as e:
        log_message(f"Error disabling maintenance mode: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/save_settings', methods=['POST'])
@login_required
@admin_required
def admin_save_settings():
    """Save system settings"""
    try:
        data = request.json
        
        settings_file = 'data/settings.json'
        os.makedirs('data', exist_ok=True)
        
        with open(settings_file, 'w') as f:
            json.dump(data, f, indent=4)
        
        log_message(f"System settings saved by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Settings saved successfully'})
        
    except Exception as e:
        log_message(f"Error saving settings: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/reset_settings', methods=['POST'])
@login_required
@admin_required
def admin_reset_settings():
    """Reset settings to defaults"""
    try:
        default_settings = {
            'site_name': 'EventFlow',
            'site_url': 'http://localhost:5000',
            'timezone': 'Asia/Kolkata',
            'email_system': 'enabled',
            'registration': 'open',
            'maintenance_mode': 'disabled',
            'contact_email': '',
            'max_file_size': 100
        }
        
        settings_file = 'data/settings.json'
        with open(settings_file, 'w') as f:
            json.dump(default_settings, f, indent=4)
        
        log_message(f"Settings reset to defaults by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Settings reset to defaults'})
        
    except Exception as e:
        log_message(f"Error resetting settings: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# Match the URL exactly as seen in your browser console: /admin/user/<id>/toggle_admin
@app.route('/admin/user/<user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    try:
        users = load_users()
        if user_id not in users:
            # Return JSON, not an HTML error, to prevent the "JSON.parse" crash
            return jsonify({'success': False, 'error': 'User not found'}), 404

        # Toggle role logic
        current_role = users[user_id].get('role', 'user')
        new_role = 'admin' if current_role != 'admin' else 'user'
        users[user_id]['role'] = new_role
        
        save_users(users)
        return jsonify({'success': True, 'message': f'User is now {new_role}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/create_backup', methods=['POST'])
@login_required
@admin_required
def admin_create_backup():
    """Create system backup"""
    try:
        import shutil
        from datetime import datetime
        
        # Create backup directory
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'{backup_dir}/backup_{timestamp}.json'
        
        # Collect backup data
        backup_data = {
            'timestamp': timestamp,
            'created_by': session.get('username'),
            'created_at': datetime.now().isoformat(),
            'users': {},
            'events': [],
            'feedback': []
        }
        
        # Backup users
        users_file = 'data/users.json'
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                backup_data['users'] = json.load(f)
        
        # Backup events
        events_dir = 'data/events'
        if os.path.exists(events_dir):
            for filename in os.listdir(events_dir):
                if filename.endswith('.json'):
                    try:
                        with open(f'{events_dir}/{filename}', 'r') as f:
                            event = json.load(f)
                            backup_data['events'].append(event)
                    except:
                        continue
        
        # Backup feedback
        feedback_file = 'data/feedback.json'
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                backup_data['feedback'] = json.load(f)
        
        # Save backup
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=4)
        
        backup_size = os.path.getsize(backup_file) / (1024*1024)  # MB
        
        log_message(f"Backup created by admin: {session.get('username')}. Size: {backup_size:.1f} MB", "ADMIN")
        return jsonify({
            'success': True, 
            'message': f'Backup created successfully ({backup_size:.1f} MB)',
            'filename': f'backup_{timestamp}.json'
        })
        
    except Exception as e:
        log_message(f"Error creating backup: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/restore_backup', methods=['POST'])
@login_required
@admin_required
def admin_restore_backup():
    """Restore system from backup"""
    try:
        data = request.json
        backup_file = data.get('backup_file')
        
        if not backup_file:
            return jsonify({'success': False, 'error': 'No backup file specified'})
        
        backup_path = f'backups/{backup_file}'
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'error': 'Backup file not found'})
        
        # Load backup data
        with open(backup_path, 'r') as f:
            backup_data = json.load(f)
        
        # Restore users
        if 'users' in backup_data:
            with open('data/users.json', 'w') as f:
                json.dump(backup_data['users'], f, indent=4)
        
        # Restore events
        if 'events' in backup_data:
            for event in backup_data['events']:
                event_id = event.get('id', str(uuid.uuid4()))
                with open(f'data/events/{event_id}.json', 'w') as f:
                    json.dump(event, f, indent=4)
        
        # Restore feedback
        if 'feedback' in backup_data:
            with open('data/feedback.json', 'w') as f:
                json.dump(backup_data['feedback'], f, indent=4)
        
        log_message(f"System restored from backup by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'Backup restored successfully'})
        
    except Exception as e:
        log_message(f"Error restoring backup: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# FEEDBACK MANAGEMENT ROUTES (Update existing ones)
# ============================================================================

# Replace the existing mark_feedback_read route with this:

@app.route('/admin/mark_feedback_read/<feedback_id>', methods=['POST'])
@login_required
def mark_feedback_read(feedback_id):
    """Mark feedback as read - UPDATED VERSION"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    feedback_data = load_feedback()
    
    updated = False
    for fb in feedback_data:
        if fb['id'] == feedback_id:
            fb['status'] = 'read'
            fb['reviewed'] = True
            fb['reviewed_at'] = datetime.now().isoformat()
            fb['reviewed_by'] = session['user_id']
            updated = True
            break
    
    if updated:
        if save_feedback(feedback_data):
            return jsonify({'success': True, 'message': 'Feedback marked as read'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
    else:
        return jsonify({'success': False, 'error': 'Feedback not found'})

# Remove the duplicate route that I suggested adding
# DO NOT add the duplicate route at line 5417

@app.route('/admin/mark_all_feedback_read', methods=['POST'])
@login_required
@admin_required
def mark_all_feedback_read():
    """Mark all feedback as read"""
    try:
        feedback_data = load_feedback()
        
        for fb in feedback_data:
            if fb.get('status') == 'new':
                fb['status'] = 'read'
                fb['reviewed'] = True
                fb['reviewed_at'] = datetime.now().isoformat()
                fb['reviewed_by'] = session['user_id']
        
        if save_feedback(feedback_data):
            count = sum(1 for fb in feedback_data if fb.get('status') == 'read')
            return jsonify({
                'success': True, 
                'message': f'Marked {count} feedback items as read'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Add route for marking feedback as responded
@app.route('/admin/mark_feedback_responded/<feedback_id>', methods=['POST'])
@login_required
@admin_required
def mark_feedback_responded(feedback_id):
    """Mark feedback as responded"""
    try:
        feedback_data = load_feedback()
        
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                fb['status'] = 'responded'
                fb['responded_at'] = datetime.now().isoformat()
                fb['responded_by'] = session['user_id']
                break
        
        if save_feedback(feedback_data):
            return jsonify({'success': True, 'message': 'Feedback marked as responded'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# USER MANAGEMENT ROUTES
# ============================================================================

@app.route('/admin/user/<user_id>')
@login_required
@admin_required
def admin_get_user(user_id):
    """Get user details - ENHANCED VERSION"""
    users = load_users()
    
    if user_id in users:
        # Get user statistics
        user_data = users[user_id].copy()
        
        # Count events created by user
        events_created = 0
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r') as f:
                        event = json.load(f)
                        if event.get('creator_id') == user_id:
                            events_created += 1
                except:
                    continue
        
        user_data['events_created'] = events_created
        
        # Count forms created by user
        forms_created = 0
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r') as f:
                        event = json.load(f)
                        if event.get('creator_id') == user_id:
                            forms_created += len(event.get('forms', []))
                except:
                    continue
        
        user_data['forms_created'] = forms_created
        
        # Count feedback submitted by user
        feedback_count = 0
        feedback_data = load_feedback()
        for fb in feedback_data:
            if fb.get('user_id') == user_id:
                feedback_count += 1
        
        user_data['feedback_count'] = feedback_count
        
        return jsonify({'success': True, 'user': user_data})
    else:
        return jsonify({'success': False, 'error': 'User not found'})
@app.route('/admin/user/<user_id>/delete', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete user"""
    try:
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Don't allow deleting admin
        if user_id == 'admin':
            return jsonify({'success': False, 'error': 'Cannot delete admin user'})
        
        # Delete user
        deleted_user = users.pop(user_id)
        
        # Save updated users
        save_users(users)
        
        # Also delete user's email status
        status_file = f'data/email_status/{user_id}.json'
        if os.path.exists(status_file):
            os.remove(status_file)
        
        log_message(f"User deleted by admin: {deleted_user.get('email')}", "ADMIN")
        return jsonify({'success': True, 'message': 'User deleted successfully'})
        
    except Exception as e:
        log_message(f"Error deleting user: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})



@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    """Create new user (admin only)"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        is_admin = data.get('is_admin', False)
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        users = load_users()
        
        # Check if email already exists
        for user_data in users.values():
            if user_data.get('email') == email:
                return jsonify({'success': False, 'error': 'Email already registered'})
        
        # Create new user
        user_id = str(uuid.uuid4())
        users[user_id] = {
            'username': username,
            'email': email,
            'mobile': data.get('mobile', ''),
            'password': password,
            'created_at': datetime.now().isoformat(),
            'email_verified': True,
            'is_admin': is_admin
        }
        
        save_users(users)
        
        log_message(f"User created by admin: {email} (Admin: {is_admin})", "ADMIN")
        return jsonify({
            'success': True, 
            'message': 'User created successfully',
            'user_id': user_id
        })
        
    except Exception as e:
        log_message(f"Error creating user: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# SYSTEM LOGS ROUTES
# ============================================================================

@app.route('/admin/get_system_logs')
@login_required
@admin_required
def admin_get_system_logs():
    """Get system logs"""
    try:
        log_file = 'logs/email.log'
        logs = []
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.readlines()
        
        # Limit to last 1000 lines
        logs = logs[-1000:]
        
        return jsonify({'success': True, 'logs': logs})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/clear_system_logs', methods=['POST'])
@login_required
@admin_required
def admin_clear_system_logs():
    """Clear system logs"""
    try:
        log_file = 'logs/email.log'
        
        if os.path.exists(log_file):
            # Instead of deleting, clear the content
            with open(log_file, 'w') as f:
                f.write('')
        
        log_message("System logs cleared by admin", "ADMIN")
        return jsonify({'success': True, 'message': 'System logs cleared'})
        
    except Exception as e:
        log_message(f"Error clearing logs: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# API MANAGEMENT ROUTES
# ============================================================================

@app.route('/admin/api_key/<key>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_api_key(key):
    """Toggle API key status"""
    try:
        api_keys_file = 'data/api_keys.json'
        api_keys = {}
        
        if os.path.exists(api_keys_file):
            with open(api_keys_file, 'r') as f:
                api_keys = json.load(f)
        
        if key in api_keys:
            current_status = api_keys[key].get('enabled', True)
            api_keys[key]['enabled'] = not current_status
            api_keys[key]['last_modified'] = datetime.now().isoformat()
            api_keys[key]['modified_by'] = session['user_id']
            
            with open(api_keys_file, 'w') as f:
                json.dump(api_keys, f, indent=4)
            
            status = 'enabled' if api_keys[key]['enabled'] else 'disabled'
            return jsonify({'success': True, 'message': f'API key {status}'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api_key/<key>/delete', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_api_key(key):
    """Delete API key"""
    try:
        api_keys_file = 'data/api_keys.json'
        api_keys = {}
        
        if os.path.exists(api_keys_file):
            with open(api_keys_file, 'r') as f:
                api_keys = json.load(f)
        
        if key in api_keys:
            deleted_key = api_keys.pop(key)
            
            with open(api_keys_file, 'w') as f:
                json.dump(api_keys, f, indent=4)
            
            log_message(f"API key deleted by admin: {deleted_key.get('name')}", "ADMIN")
            return jsonify({'success': True, 'message': 'API key deleted'})
        else:
            return jsonify({'success': False, 'error': 'API key not found'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# DEBUG TOOLS ROUTES
# ============================================================================

@app.route('/admin/test_database', methods=['POST'])
@login_required
@admin_required
def admin_test_database():
    """Test database connection"""
    try:
        # Test users database
        users = load_users()
        users_count = len(users)
        
        # Test events database
        event_files = [f for f in os.listdir('data/events') if f.endswith('.json')]
        events_count = len(event_files)
        
        # Test feedback database
        feedback_data = load_feedback()
        feedback_count = len(feedback_data)
        
        return jsonify({
            'success': True,
            'message': 'Database test completed',
            'results': {
                'users_count': users_count,
                'events_count': events_count,
                'feedback_count': feedback_count,
                'status': 'OK'
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'status': 'FAILED'})

@app.route('/admin/test_smtp', methods=['POST'])
@login_required
@admin_required
def admin_test_smtp():
    """Test SMTP server connection"""
    try:
        import smtplib
        
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.quit()
        
        return jsonify({
            'success': True,
            'message': 'SMTP server connection successful',
            'server': MAIL_SERVER,
            'port': MAIL_PORT
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/check_file_permissions', methods=['POST'])
@login_required
@admin_required
def admin_check_file_permissions():
    """Check file permissions"""
    try:
        directories = ['data', 'data/events', 'static/uploads', 'logs', 'reports']
        files = ['data/users.json', 'data/feedback.json']
        
        results = []
        
        # Check directories
        for directory in directories:
            if os.path.exists(directory):
                try:
                    # Try to create a test file
                    test_file = os.path.join(directory, '.test_permission')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    results.append({'path': directory, 'status': 'writable', 'error': None})
                except Exception as e:
                    results.append({'path': directory, 'status': 'read-only', 'error': str(e)})
            else:
                results.append({'path': directory, 'status': 'not_exists', 'error': 'Directory does not exist'})
        
        # Check files
        for file in files:
            if os.path.exists(file):
                try:
                    # Try to read and write
                    with open(file, 'r') as f:
                        content = f.read()
                    with open(file, 'w') as f:
                        f.write(content)
                    results.append({'path': file, 'status': 'writable', 'error': None})
                except Exception as e:
                    results.append({'path': file, 'status': 'read-only', 'error': str(e)})
            else:
                results.append({'path': file, 'status': 'not_exists', 'error': 'File does not exist'})
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# FEEDBACK SETTINGS ROUTES
# ============================================================================

@app.route('/admin/feedback_settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_feedback_settings():
    """Manage feedback settings"""
    settings_file = 'data/feedback_settings.json'
    
    if request.method == 'POST':
        try:
            settings = {
                'notify_admin_on_feedback': request.form.get('notify_admin') == 'on',
                'admin_email': request.form.get('admin_email', ''),
                'auto_respond_feedback': request.form.get('auto_respond') == 'on',
                'feedback_response_email': request.form.get('response_email', ''),
                'require_email_for_feedback': request.form.get('require_email') == 'on',
                'allow_anonymous_feedback': request.form.get('allow_anonymous') == 'on',
                'max_feedback_length': int(request.form.get('max_length', 1000))
            }
            
            os.makedirs('data', exist_ok=True)
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            
            flash('Feedback settings saved!', 'success')
            return redirect(url_for('admin_feedback_settings'))
            
        except Exception as e:
            flash(f'Error saving settings: {str(e)}', 'error')
    
    # Load existing settings
    settings = {}
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            settings = json.load(f)
    
    return render_template('admin_feedback_settings.html',
                         page_title='Feedback Settings',
                         active_page='feedback_settings',
                         settings=settings)

# ============================================================================
# EXPORT ROUTES
# ============================================================================

@app.route('/admin/export_feedback')
@login_required
@admin_required
def admin_export_feedback():
    """Export feedback as CSV"""
    try:
        feedback_data = load_feedback()
        
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Name', 'Email', 'Rating', 'Type', 'Message', 'Status', 'Timestamp', 'Source', 'Context'])
        
        # Write data
        for fb in feedback_data:
            writer.writerow([
                fb.get('id', ''),
                fb.get('name', ''),
                fb.get('email', ''),
                fb.get('rating', ''),
                fb.get('type', ''),
                fb.get('message', ''),
                fb.get('status', ''),
                fb.get('timestamp', ''),
                fb.get('source', ''),
                fb.get('context', '')
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=feedback_export.csv'
        response.headers['Content-type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting feedback: {str(e)}', 'error')
        return redirect(url_for('admin_feedback_receiver'))

@app.route('/admin/export_users')
@login_required
@admin_required
def admin_export_users():
    """Export users as CSV"""
    try:
        users = load_users()
        
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['User ID', 'Username', 'Email', 'Mobile', 'Created At', 'Email Verified', 'Is Admin'])
        
        # Write data
        for user_id, user_data in users.items():
            writer.writerow([
                user_id,
                user_data.get('username', ''),
                user_data.get('email', ''),
                user_data.get('mobile', ''),
                user_data.get('created_at', ''),
                user_data.get('email_verified', False),
                user_data.get('is_admin', False)
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=users_export.csv'
        response.headers['Content-type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting users: {str(e)}', 'error')
        return redirect(url_for('admin_user_management'))

@app.route('/admin/export_events')
@login_required
@admin_required
def admin_export_events():
    """Export events as CSV"""
    try:
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Event ID', 'Name', 'Description', 'Category', 'Type', 'Creator ID', 'Created At', 'Form Count'])
        
        # Write data
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r') as f:
                        event = json.load(f)
                    
                    writer.writerow([
                        event.get('id', ''),
                        event.get('name', ''),
                        event.get('description', ''),
                        event.get('category', ''),
                        event.get('type', ''),
                        event.get('creator_id', ''),
                        event.get('created_at', ''),
                        len(event.get('forms', []))
                    ])
                except:
                    continue
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=events_export.csv'
        response.headers['Content-type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting events: {str(e)}', 'error')
        return redirect(url_for('admin_statistics'))

@app.route('/ip_debug')
def ip_debug():
    """Debug endpoint to see all IP-related headers"""
    html = """
    <html>
    <head>
        <title>IP Debug</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .header { background: #f0f0f0; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }
            .ip { color: #28a745; font-weight: bold; }
            .detected { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1>IP Detection Debug</h1>
        
        <div class="detected">
            <h3>Detected IPv4: <span class="ip">""" + get_real_ip() + """</span></h3>
        </div>
        
        <h2>All Headers:</h2>
    """
    
    for header, value in request.headers:
        html += f'<div class="header"><strong>{header}:</strong> {value}</div>'
    
    html += f"""
        <h2>Request Info:</h2>
        <div class="header"><strong>remote_addr:</strong> {request.remote_addr}</div>
        <div class="header"><strong>scheme:</strong> {request.scheme}</div>
        <div class="header"><strong>method:</strong> {request.method}</div>
        
        <h2>Test Form Submission:</h2>
        <form action="/test_form_submission" method="POST">
            <input type="text" name="test_field" value="Test Value">
            <button type="submit">Test Submit</button>
        </form>
    </body>
    </html>
    """
    
    return html


@app.route('/test_form_submission', methods=['POST'])
def test_form_submission():
    """Test form submission to see IP"""
    ip = get_real_ip()
    
    return f"""
    <html>
    <body>
        <h2>Test Form Submission Result</h2>
        <p><strong>Detected IPv4:</strong> {ip}</p>
        <p><strong>X-Forwarded-For:</strong> {request.headers.get('X-Forwarded-For')}</p>
        <p><strong>X-Real-IP:</strong> {request.headers.get('X-Real-IP')}</p>
        <p><a href="/ip_debug">Back to Debug</a></p>
    </body>
    </html>
    """
@app.route('/admin/export_statistics_csv')
@login_required
@admin_required
def admin_export_statistics_csv():
    """Export statistics as CSV"""
    try:
        # Get statistics data
        stats = get_server_statistics()
        
        # Create CSV content
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Metric', 'Value', 'Description'])
        
        # Write data
        writer.writerow(['Total Users', stats['users'], 'Number of registered users'])
        writer.writerow(['Total Events', stats['events'], 'Number of created events'])
        writer.writerow(['Total Forms', stats['forms'], 'Number of registration forms'])
        writer.writerow(['Total Registrations', stats['registrations'], 'Number of form submissions'])
        
        # Add additional statistics if available
        import psutil
        import os
        
        # System info
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        writer.writerow(['CPU Usage %', f'{cpu_percent:.1f}', 'Current CPU utilization'])
        writer.writerow(['Memory Usage %', f'{memory.percent:.1f}', 'Current memory utilization'])
        
        # Storage usage
        storage_used_mb = 0
        for root, dirs, files in os.walk('.'):
            for file in files:
                if any(x in root for x in ['data', 'static/uploads', 'logs', 'reports']):
                    try:
                        filepath = os.path.join(root, file)
                        storage_used_mb += os.path.getsize(filepath) / (1024 * 1024)
                    except:
                        continue
        
        writer.writerow(['Storage Used (MB)', f'{storage_used_mb:.2f}', 'Total storage used by app'])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=statistics_export.csv'
        response.headers['Content-type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting statistics: {str(e)}', 'error')
        return redirect(url_for('admin_statistics'))

# ============================================================================
# IMPORT ROUTES
# ============================================================================

@app.route('/admin/import_users', methods=['POST'])
@login_required
@admin_required
def admin_import_users():
    """Import users from CSV"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('admin_user_management'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('admin_user_management'))
        
        if not file.filename.endswith('.csv'):
            flash('Only CSV files are allowed', 'error')
            return redirect(url_for('admin_user_management'))
        
        import csv
        import io
        
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        users = load_users()
        imported_count = 0
        skipped_count = 0
        
        for row in csv_reader:
            email = row.get('Email', '').strip()
            
            # Check if user already exists
            user_exists = False
            for user_data in users.values():
                if user_data.get('email') == email:
                    user_exists = True
                    break
            
            if not user_exists and email:
                user_id = str(uuid.uuid4())
                users[user_id] = {
                    'username': row.get('Username', email.split('@')[0]),
                    'email': email,
                    'mobile': row.get('Mobile', ''),
                    'password': row.get('Password', 'password123'),
                    'created_at': datetime.now().isoformat(),
                    'email_verified': row.get('Email Verified', '').lower() == 'true',
                    'is_admin': row.get('Is Admin', '').lower() == 'true'
                }
                imported_count += 1
            else:
                skipped_count += 1
        
        save_users(users)
        
        flash(f'Successfully imported {imported_count} users. Skipped {skipped_count} existing users.', 'success')
        return redirect(url_for('admin_user_management'))
        
    except Exception as e:
        flash(f'Error importing users: {str(e)}', 'error')
        return redirect(url_for('admin_user_management'))

                             
# ========== ADMIN ROUTES ==========

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    """Admin system settings page."""
    settings_file = 'data/settings.json'
    
    if request.method == 'POST':
        try:
            settings = {
                'site_name': request.form.get('site_name', 'EventFlow'),
                'site_url': request.form.get('site_url', 'http://localhost:5000'),
                'timezone': request.form.get('timezone', 'Asia/Kolkata'),
                'email_system': request.form.get('email_system', 'enabled'),
                'registration': request.form.get('registration', 'open'),
                'maintenance_mode': request.form.get('maintenance_mode', 'disabled'),
                'contact_email': request.form.get('contact_email', ''),
                'max_file_size': int(request.form.get('max_file_size', 100))
            }
            
            os.makedirs('data', exist_ok=True)
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            
            flash('Settings saved successfully!', 'success')
            return redirect(url_for('admin_settings'))
            
        except Exception as e:
            flash(f'Error saving settings: {str(e)}', 'error')
    
    # Load existing settings
    settings = {}
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            settings = json.load(f)
    
    return render_template('admin_settings.html',
                         page_title='System Settings',
                         active_page='admin_settings',
                         settings=settings)

@app.route('/test_with_resend_domain')
def test_with_resend_domain():
    """Test with Resend's verified domain"""
    try:
        test_email = "eventflow.app2026@gmail.com"
        
        success, message = send_email_simple(
            test_email,
            "✅ Using Resend's Verified Domain",
            """
            <h2>Resend Domain Test</h2>
            <p>This uses <code>onboarding@resend.dev</code> - already verified!</p>
            <p>Ready for Render deployment.</p>
            """
        )
        
        return jsonify({
            'success': success,
            'message': message,
            'sender_used': os.environ.get('MAIL_DEFAULT_SENDER')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/users')
@login_required
@admin_required
def admin_user_management():
    """Admin user management page."""
    users = {}
    if os.path.exists('data/users.json'):
        with open(get_data_path('users.json'), 'r') as f:
            users = json.load(f)
    
    # Calculate stats
    total_users = len(users)
    active_today = 0  # You could implement session tracking for this
    admins = sum(1 for user in users.values() if user.get('is_admin', False))
    
    return render_template('admin_users.html',
                         page_title='User Management',
                         active_page='admin_users',
                         users=users,
                         total_users=total_users,
                         active_today=active_today,
                         admins=admins)

@app.route('/admin/logs')
@login_required
@admin_required
def admin_system_logs():
    """Admin system logs page."""
    logs = []
    log_file = 'data/system_logs.json'
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = json.load(f)
    
    return render_template('admin_logs.html',
                         page_title='System Logs',
                         active_page='admin_logs',
                         logs=logs)

@app.route('/admin/backup', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_backup_restore():
    """Admin backup/restore page."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_backup':
            try:
                # Create backup directory
                backup_dir = 'backups'
                os.makedirs(backup_dir, exist_ok=True)
                
                # Generate backup filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_file = f'{backup_dir}/backup_{timestamp}.zip'
                
                # Create a simple backup (in real app, you'd zip files)
                backup_data = {
                    'timestamp': timestamp,
                    'files': []
                }
                
                # Backup users
                if os.path.exists('data/users.json'):
                    with open('data/users.json', 'r') as f:
                        backup_data['users'] = json.load(f)
                
                # Backup events
                if os.path.exists('data/events.json'):
                    with open('data/events.json', 'r') as f:
                        backup_data['events'] = json.load(f)
                
                # Save backup
                with open(f'{backup_dir}/backup_{timestamp}.json', 'w') as f:
                    json.dump(backup_data, f, indent=4)
                
                flash(f'Backup created successfully: backup_{timestamp}.json', 'success')
                
            except Exception as e:
                flash(f'Error creating backup: {str(e)}', 'error')
        
        elif action == 'clear_backups':
            try:
                backup_dir = 'backups'
                if os.path.exists(backup_dir):
                    for file in os.listdir(backup_dir):
                        os.remove(os.path.join(backup_dir, file))
                    flash('All backups cleared successfully!', 'success')
            except Exception as e:
                flash(f'Error clearing backups: {str(e)}', 'error')
    
    # List existing backups
    backups = []
    backup_dir = 'backups'
    if os.path.exists(backup_dir):
        backups = sorted(os.listdir(backup_dir))
    
    return render_template('admin_backup.html',
                         page_title='Backup & Restore',
                         active_page='admin_backup',
                         backups=backups)

@app.route('/admin/security', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_security():
    """Admin security settings page."""
    if request.method == 'POST':
        # Handle security settings updates
        flash('Security settings updated!', 'success')
    
    return render_template('admin_security.html',
                         page_title='Security Center',
                         active_page='admin_security')

@app.route('/admin/get_current_user_id')
@login_required
def get_current_user_id():
    """Get current user ID for frontend checks"""
    return jsonify({
        'success': True,
        'user_id': session.get('user_id')
    })

@app.route('/admin/api', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_api_management():
    """Admin API management page."""
    api_keys_file = 'data/api_keys.json'
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate_key':
            try:
                # Load existing keys
                api_keys = {}
                if os.path.exists(api_keys_file):
                    with open(api_keys_file, 'r') as f:
                        api_keys = json.load(f)
                
                # Generate new key
                import secrets
                new_key = secrets.token_hex(32)
                key_name = request.form.get('key_name', 'New API Key')
                
                api_keys[new_key] = {
                    'name': key_name,
                    'created': datetime.now().isoformat(),
                    'last_used': None,
                    'enabled': True
                }
                
                # Save keys
                os.makedirs('data', exist_ok=True)
                with open(api_keys_file, 'w') as f:
                    json.dump(api_keys, f, indent=4)
                
                flash(f'API key generated: {new_key}', 'success')
                
            except Exception as e:
                flash(f'Error generating API key: {str(e)}', 'error')
    
    # Load API keys
    api_keys = {}
    if os.path.exists(api_keys_file):
        with open(api_keys_file, 'r') as f:
            api_keys = json.load(f)
    
    return render_template('admin_api.html',
                         page_title='API Management',
                         active_page='admin_api',
                         api_keys=api_keys)

@app.route('/admin/debug', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_debug_tools():
    """Admin debug tools page."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'clear_cache':
            try:
                # Clear session data
                session.clear()
                flash('Cache cleared successfully!', 'success')
            except Exception as e:
                flash(f'Error clearing cache: {str(e)}', 'error')
        
        elif action == 'test_email':
            try:
                # Test email functionality
                test_email = request.form.get('test_email', session.get('email'))
                if test_email:
                    # You would implement actual email sending here
                    flash(f'Test email would be sent to {test_email}', 'info')
                else:
                    flash('Please provide an email address', 'error')
            except Exception as e:
                flash(f'Error testing email: {str(e)}', 'error')
    
    return render_template('admin_debug.html',
                         page_title='Debug Tools',
                         active_page='admin_debug')

@app.route('/admin/statistics')
@login_required
@admin_required
def admin_statistics():
    """Admin statistics page - UPDATED WITH REAL DATA"""
    # Calculate real statistics
    stats = get_server_statistics()  # Your existing function
    
    # Calculate additional real statistics
    import psutil
    import os
    
    # System performance metrics
    cpu_percentage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Calculate today's activity
    today = datetime.now().date()
    today_users = 0
    today_events = 0
    today_forms = 0
    today_submissions = 0
    
    # Get users created today
    users = load_users()
    for user_data in users.values():
        created_date = datetime.fromisoformat(user_data.get('created_at', '2000-01-01')).date()
        if created_date == today:
            today_users += 1
    
    # Get events created today
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    created_date = datetime.fromisoformat(event.get('created_at', '2000-01-01')).date()
                    if created_date == today:
                        today_events += 1
                        today_forms += len(event.get('forms', []))
            except:
                continue
    
    # Get submissions today (this would need tracking in your CSV files)
    # For now, we'll estimate based on recent activity
    
    # Calculate active forms
    active_forms = 0
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    for form in event.get('forms', []):
                        # Check if form has schedule and is active
                        schedule = form.get('schedule', {})
                        if not schedule or schedule.get('enabled') == False:
                            active_forms += 1
                        else:
                            # Check if form is currently active based on schedule
                            import datetime as dt
                            now = datetime.now()
                            
                            start_datetime = schedule.get('start_datetime')
                            end_datetime = schedule.get('end_datetime')
                            
                            is_active = True
                            if start_datetime:
                                start_time = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
                                if now < start_time:
                                    is_active = False
                            
                            if end_datetime:
                                end_time = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
                                if now > end_time:
                                    is_active = False
                            
                            if is_active:
                                active_forms += 1
            except:
                continue
    
    # Get pending feedback
    feedback_data = load_feedback()
    pending_feedback = sum(1 for fb in feedback_data if fb.get('status') == 'new')
    
    # Calculate storage usage
    storage_used_mb = 0
    database_size_mb = 0
    log_size_mb = 0
    
    # Calculate total storage used
    for root, dirs, files in os.walk('.'):
        for file in files:
            if any(x in root for x in ['data', 'static/uploads', 'logs', 'reports']):
                try:
                    filepath = os.path.join(root, file)
                    storage_used_mb += os.path.getsize(filepath) / (1024 * 1024)
                    
                    if 'data' in root and file.endswith('.json'):
                        database_size_mb += os.path.getsize(filepath) / (1024 * 1024)
                    elif 'logs' in root:
                        log_size_mb += os.path.getsize(filepath) / (1024 * 1024)
                except:
                    continue
    
    # Get recent activity (last 5 activities)
    recent_activity = []
    
    # Add user signups
    for user_id, user_data in list(users.items())[-3:]:  # Last 3 users
        created_time = datetime.fromisoformat(user_data.get('created_at', datetime.now().isoformat()))
        time_ago = (datetime.now() - created_time)
        
        if time_ago.days == 0:
            hours_ago = time_ago.seconds // 3600
            if hours_ago == 0:
                minutes_ago = time_ago.seconds // 60
                time_text = f"{minutes_ago} minute{'s' if minutes_ago != 1 else ''} ago"
            else:
                time_text = f"{hours_ago} hour{'s' if hours_ago != 1 else ''} ago"
        else:
            time_text = f"{time_ago.days} day{'s' if time_ago.days != 1 else ''} ago"
        
        recent_activity.append({
            'type': 'user_signup',
            'title': 'New User Registration',
            'description': f"User: {user_data.get('username', 'Unknown')}",
            'time_ago': time_text
        })
    
    # Add recent events
    event_files = sorted([f for f in os.listdir('data/events') if f.endswith('.json')], 
                        key=lambda x: os.path.getmtime(f'data/events/{x}'), 
                        reverse=True)[:2]
    
    for event_file in event_files:
        try:
            with open(f'data/events/{event_file}', 'r') as f:
                event = json.load(f)
            
            created_time = datetime.fromisoformat(event.get('created_at', datetime.now().isoformat()))
            time_ago = (datetime.now() - created_time)
            
            if time_ago.days == 0:
                hours_ago = time_ago.seconds // 3600
                if hours_ago == 0:
                    minutes_ago = time_ago.seconds // 60
                    time_text = f"{minutes_ago} minute{'s' if minutes_ago != 1 else ''} ago"
                else:
                    time_text = f"{hours_ago} hour{'s' if hours_ago != 1 else ''} ago"
            else:
                time_text = f"{time_ago.days} day{'s' if time_ago.days != 1 else ''} ago"
            
            recent_activity.append({
                'type': 'event_created',
                'title': 'Event Created',
                'description': f"Event: {event.get('name', 'Unknown')}",
                'time_ago': time_text
            })
        except:
            continue
    
    # Limit to 5 recent activities
    recent_activity = recent_activity[:5]
    
    # Enhanced stats dictionary
    enhanced_stats = {
        # Basic stats from your existing function
        'total_users': stats['users'],
        'total_events': stats['events'],
        'total_forms': stats['forms'],
        'total_submissions': stats['registrations'],
        
        # Today's activity
        'today_activity': {
            'today_users': today_users,
            'today_events': today_events,
            'today_forms': today_forms,
            'today_submissions': today_submissions
        },
        
        # This month stats (simplified - you'd need to calculate properly)
        'this_month_stats': {
            'month_users': today_users * 30,  # Estimate
            'month_events': today_events * 30,  # Estimate
            'month_forms': today_forms * 30,  # Estimate
        },
        
        # System metrics
        'active_forms': active_forms,
        'pending_feedback': pending_feedback,
        'active_sessions': len([uid for uid in users if True]),  # Simplified
        'database_status': 'healthy' if os.path.exists('data/users.json') else 'unhealthy',
        
        # Storage metrics
        'storage_used_mb': round(storage_used_mb, 2),
        'storage_percentage': round((storage_used_mb / 1024) * 100, 1),  # Assuming 1GB total
        'database_size_mb': round(database_size_mb, 2),
        'log_size_mb': round(log_size_mb, 2),
        
        # Performance metrics
        'memory_percentage': round(memory.percent, 1),
        'cpu_percentage': round(cpu_percentage, 1),
        'uptime_percentage': 99.8,  # Would need to track server start time
        'avg_response_time': 0.2,  # Would need to measure
        'success_rate': 98,  # Would need to track
        
        # System info
        'system_uptime': '24h 15m',  # Would need to calculate
        'server_start_time': '2024-01-15 08:00:00',  # Would need to track
        
        # Recent activity
        'recent_activity': recent_activity
    }
    
    return render_template('admin_statistics.html',
                         page_title='System Statistics',
                         active_page='admin_statistics',
                         stats=enhanced_stats,
                         now=datetime.now(),
                         python_version=platform.python_version(),
                         flask_version=flask.__version__)
                         
@app.route('/admin/debug/form/<form_id>')
@login_required
def admin_debug_form(form_id):
    """Admin-only form debugging page"""
    if session.get('user_id') != 'admin':  # Adjust based on your admin check
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    form_found = False
    event_found = None
    form_data = None
    events_checked = []
    
    # Detailed search with debug info
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                    event = json.load(f)
                
                event_info = {
                    'filename': filename,
                    'event_id': event.get('id'),
                    'event_name': event.get('name'),
                    'form_count': len(event.get('forms', [])),
                    'found_match': False,
                    'error': None
                }
                
                for form in event.get('forms', []):
                    if form['id'] == form_id:
                        event_info['found_match'] = True
                        form_found = True
                        event_found = event
                        form_data = form
                        break
                
                events_checked.append(event_info)
                
            except Exception as e:
                events_checked.append({
                    'filename': filename,
                    'error': str(e),
                    'found_match': False
                })
    
    # Prepare debug information
    debug_info = {
        'found': form_found,
        'events_checked': events_checked,
        'form_id': form_id
    }
    
    if form_found:
        is_active, message = check_form_active_status(form_data)
        debug_info.update({
            'event_name': event_found.get('name'),
            'form_title': form_data.get('title'),
            'is_active': is_active,
            'message': message,
            'form_data': form_data  # Be careful with this in production
        })
    
    return render_template('form_debug.html',
                         form_id=form_id,
                         debug_info=debug_info)

@app.route('/debug/find-form/<form_id>')
@login_required
def debug_find_form(form_id):
    """Debug endpoint to find a specific form - admin only"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    # Redirect to admin debug page
    return redirect(url_for('admin_debug_form', form_id=form_id))

@app.route('/submit_form/<form_id>', methods=['POST'])
def submit_form(form_id):
    """Handle form submissions with bot protection - returns JSON for AJAX"""
    try:
        # ==================== IP DETECTION ====================
        # Simple but effective IP extraction
        import re
        
        attendee_ip = '0.0.0.0'
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        
        if x_forwarded_for:
            # Get first IP in chain
            first_ip = x_forwarded_for.split(',')[0].strip()
            
            # Try to extract IPv4 using regex
            ipv4_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', first_ip)
            if ipv4_match:
                attendee_ip = ipv4_match.group(1)
                # Validate it's a real IPv4
                parts = attendee_ip.split('.')
                valid = len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
                if not valid:
                    attendee_ip = '0.0.0.0'
            # If IPv6, create pseudo IPv4
            elif ':' in first_ip:
                # Create consistent pseudo-IP from IPv6 hash
                import hashlib
                hash_obj = hashlib.md5(first_ip.encode())
                hash_hex = hash_obj.hexdigest()
                # Convert to 10.x.x.x format
                attendee_ip = f"10.{int(hash_hex[0:2], 16)}.{int(hash_hex[2:4], 16)}.{int(hash_hex[4:6], 16)}"
        
        print(f"Form {form_id} submission from IP: {attendee_ip}")
        
        # ==================== BOT PROTECTION ====================
        # Honeypot check
        if request.form.get('human_check', '').strip():
            return jsonify({
                'success': True,
                'message': 'Form submitted successfully!',
                'is_bot': True,
                'redirect': url_for('show_form', form_id=form_id)
            })
        
        # Advanced bot protection
        allowed, reason = bot_protector.check_and_block(form_id, attendee_ip)
        if not allowed:
            return jsonify({
                'success': False,
                'message': f'❌ {reason}',
                'redirect': url_for('show_form', form_id=form_id)
            })
        # ==================== END BOT PROTECTION ====================
        
        # Find the form and event
        form_found = False
        event_data = None
        form_data = None
        
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                        event = json.load(f)
                        for form in event.get('forms', []):
                            if form['id'] == form_id:
                                form_found = True
                                event_data = event
                                form_data = form
                                break
                        if form_found:
                            break
                except Exception as e:
                    print(f"Error reading event file {filename}: {e}")
                    continue
        
        if not form_found:
            return jsonify({
                'success': False,
                'message': 'Form not found!',
                'redirect': url_for('index')
            })
        
        # Check if form is active
        is_active, message = check_form_active_status(form_data)
        if not is_active:
            return jsonify({
                'success': False,
                'message': f'Cannot submit: {message}',
                'redirect': url_for('show_form', form_id=form_id)
            })
        
        # Form is active, process submission
        event_id = event_data["id"]
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        # DEBUG: Check existing CSV
        needs_new_csv = False
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    headers = next(reader, [])
                    print(f"DEBUG: Existing CSV headers: {headers}")
                    
                    # Check if headers match form questions
                    expected_headers = ['Timestamp', 'Response ID', 'Attendee IP']
                    expected_headers += [q['text'] for q in form_data['questions']]
                    
                    if headers != expected_headers:
                        print(f"DEBUG: Headers don't match! Expected: {expected_headers}")
                        needs_new_csv = True
            except Exception as e:
                print(f"DEBUG: Error reading CSV: {e}")
                needs_new_csv = True
        
        # Prepare response data
        response_id = str(uuid.uuid4())
        response_data = [
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            response_id,
            attendee_ip
        ]
        
        uploaded_files_count = 0
        uploaded_filenames = []
        
        # Process each question
        for question in form_data['questions']:
            question_text = question['text']
            question_id = question['id']
            
            if question['type'] == 'file':
                file_field = f"file_{question_id}"
                if file_field in request.files:
                    file = request.files[file_field]
                    if file and file.filename:
                        # Get file settings
                        file_settings = question.get('file_settings', {})
                        
                        # Check if multiple files allowed
                        if file_settings.get('multiple', False):
                            files = request.files.getlist(file_field)
                            filenames = []
                            for f in files:
                                if f and f.filename:
                                    if allowed_file_with_settings(f, file_settings):
                                        filename = secure_filename(f.filename)
                                        unique_name = f"{uuid.uuid4().hex}_{filename}"
                                        upload_dir = f"static/uploads/events/{event_id}/{form_id}"
                                        os.makedirs(upload_dir, exist_ok=True)
                                        file_path = os.path.join(upload_dir, unique_name)
                                        f.save(file_path)
                                        filenames.append(unique_name)
                                        uploaded_files_count += 1
                                        uploaded_filenames.append({
                                            'original': filename,
                                            'saved_as': unique_name,
                                            'question': question_text
                                        })
                                    else:
                                        return jsonify({
                                            'success': False,
                                            'message': f'Invalid file type or size for {question_text}',
                                            'redirect': url_for('show_form', form_id=form_id)
                                        })
                            response_data.append(', '.join(filenames))
                        else:
                            # Single file
                            if allowed_file_with_settings(file, file_settings):
                                filename = secure_filename(file.filename)
                                unique_name = f"{uuid.uuid4().hex}_{filename}"
                                upload_dir = f"static/uploads/events/{event_id}/{form_id}"
                                os.makedirs(upload_dir, exist_ok=True)
                                file_path = os.path.join(upload_dir, unique_name)
                                file.save(file_path)
                                response_data.append(unique_name)
                                uploaded_files_count += 1
                                uploaded_filenames.append({
                                    'original': filename,
                                    'saved_as': unique_name,
                                    'question': question_text
                                })
                            else:
                                return jsonify({
                                    'success': False,
                                    'message': f'Invalid file type or size for {question_text}',
                                    'redirect': url_for('show_form', form_id=form_id)
                                })
                    else:
                        response_data.append('')
                else:
                    response_data.append('')
                    
            elif question['type'] == 'checkbox':
                values = request.form.getlist(f"q_{question_id}")
                response_data.append(', '.join(values))
                
            else:
                response_data.append(request.form.get(f"q_{question_id}", ''))
        
        # Save to CSV
        if not os.path.exists(csv_path) or needs_new_csv:
            # Create new CSV with correct headers
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Create headers
                headers = ['Timestamp', 'Response ID', 'Attendee IP']
                headers += [q['text'] for q in form_data['questions']]
                writer.writerow(headers)
                writer.writerow(response_data)
        else:
            # Append to existing CSV
            with open(csv_path, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(response_data)
        
        # Log the submission
        log_message(f"Form {form_id} submitted. IP: {attendee_ip}, Response ID: {response_id}", "SUBMISSION")
        
        # Return success JSON
        return jsonify({
            'success': True,
            'message': '✅ Form submitted successfully!',
            'response_id': response_id,
            'attendee_ip': attendee_ip,
            'uploaded_files': uploaded_files_count,
            'timestamp': response_data[0],
            'redirect': url_for('show_form', form_id=form_id),
            'form_url': url_for('show_form', form_id=form_id, _external=True)
        })
        
    except Exception as e:
        log_message(f"Error processing submission for form {form_id}: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)[:100]}...',
            'error': str(e),
            'redirect': url_for('show_form', form_id=form_id)
        }), 500

@app.route('/test_resend_working')
def test_resend_working():
    """Test if Resend API is working"""
    try:
        test_email = "eventflow.app2026@gmail.com"
        
        success, message = send_email_simple(
            test_email,
            "🎉 Resend Test Email - EventFlow",
            """
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>✅ Resend Email Test SUCCESSFUL!</h2>
                <p>This email was sent using <strong>Resend API</strong>.</p>
                <p>Your email system is now ready for Render deployment.</p>
                <p>Time: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                <hr>
                <p><small>EventFlow Email System</small></p>
            </body>
            </html>
            """
        )
        
        return jsonify({
            'success': success,
            'message': message,
            'test_email': test_email,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'help': 'Check your Resend API key and sender email verification'
        })

@app.route('/admin/fix_form_csv/<event_id>/<form_id>', methods=['POST'])
@login_required
@admin_required
def admin_fix_form_csv(event_id, form_id):
    """Fix CSV headers for a form that has corrupted headers"""
    try:
        event = load_event(event_id)
        if not event:
            return jsonify({'success': False, 'error': 'Event not found'})
        
        # Find the form
        form_data = None
        for form in event.get('forms', []):
            if form['id'] == form_id:
                form_data = form
                break
        
        if not form_data:
            return jsonify({'success': False, 'error': 'Form not found'})
        
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return jsonify({'success': False, 'error': 'CSV file not found'})
        
        # Read existing data (skip the corrupted header)
        rows = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0:
                    print(f"Current header: {row}")
                rows.append(row)
        
        # Create new CSV with correct headers
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Correct headers
            headers = ['Timestamp', 'Response ID', 'Attendee IP']
            headers += [q['text'] for q in form_data['questions']]
            writer.writerow(headers)
            
            # Write existing data rows (skip first if it was a header row)
            for i, row in enumerate(rows):
                if i > 0 and len(row) > 0:
                    # Ensure row has right number of columns
                    while len(row) < len(headers):
                        row.append('')
                    while len(row) > len(headers):
                        row.pop()
                    writer.writerow(row)
        
        return jsonify({
            'success': True,
            'message': f'CSV fixed with {len(headers)} columns',
            'headers': headers,
            'rows_fixed': len(rows) - 1
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})        
        
# ============================================================================
# PUBLIC FORM ROUTE
# ============================================================================

# In app.py
from markupsafe import Markup
import re

def nl2br(value):
    """Convert newline characters to <br> tags"""
    if value is None:
        return ''
    # Replace all types of newline characters
    result = re.sub(r'\r\n|\n|\r', '<br>', str(value))
    return Markup(result)  # Markup ensures HTML tags are not escaped

# Register the filter
app.jinja_env.filters['nl2br'] = nl2br

@app.route('/form/<form_id>')
def show_form(form_id):
    """Show form for public submissions with schedule checking"""
    # First check if form is blocked
    is_blocked, block_reason, block_timestamp, block_data = check_form_blocked_enhanced(form_id)
    
    if is_blocked:
        # Check if current user is admin
        is_admin_user = session.get('user_id') == 'admin'
        
        # If user is admin, show the form anyway with a warning
        if is_admin_user:
            flash(f'⚠️ ADMIN VIEW: This form is blocked. Reason: {block_reason}', 'warning')
            flash(f'📅 Blocked since: {block_timestamp}', 'info')
            # Continue to show the form (don't return blocked page)
        else:
            # Non-admin users see the blocked page
            return show_blocked_form_page(form_id, block_reason, block_timestamp)
    
    # If not blocked or admin is viewing, continue with normal form display
    form_found = False
    event_found = None
    form_data = None
    events_checked = []
    
    # Search for the form
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                    event = json.load(f)
                
                for form in event.get('forms', []):
                    if form['id'] == form_id:
                        form_found = True
                        event_found = event
                        form_data = form
                        break
                
                if form_found:
                    break
                    
            except Exception as e:
                continue
    
    if form_found and event_found and form_data:
        # Get creator information
        creator_info = {}
        creator_id = event_found.get('creator_id')
        
        if creator_id:
            users = load_users()
            creator_data = users.get(creator_id)
            
            if creator_data:
                creator_info = {
                    'user_id': creator_id,
                    'name': creator_data.get('username', 'Unknown User'),
                    'email': creator_data.get('email', ''),
                    'verified': creator_data.get('email_verified', False),
                    'join_date': creator_data.get('created_at', ''),
                    'events_created': 0
                }
                
                # Count events created by this user
                for ev_file in os.listdir('data/events'):
                    if ev_file.endswith('.json'):
                        try:
                            with open(f'data/events/{ev_file}', 'r') as f:
                                ev = json.load(f)
                                if ev.get('creator_id') == creator_id:
                                    creator_info['events_created'] += 1
                        except:
                            continue
        
        # Check if form is active
        is_active, message = check_form_active_status(form_data)
        
        # Make a copy of the form to avoid modifying original
        form_copy = dict(form_data) if form_data else {}
        
        # FIX: Ensure schedule exists and is a dictionary
        # Check if schedule is None or doesn't exist
        if 'schedule' not in form_copy or form_copy.get('schedule') is None:
            form_copy['schedule'] = {}
        
        # Now safely assign to schedule
        form_copy['schedule']['status_message'] = message
        form_copy['schedule']['is_active'] = is_active
        
        if not is_active:
            # Show inactive form page with schedule information
            return render_template('form_inactive.html', 
                                 form=form_copy, 
                                 event=event_found,
                                 message=message,
                                 form_id=form_id,
                                 creator_info=creator_info,
                                 is_blocked=is_blocked,
                                 block_reason=block_reason if is_blocked else None,
                                 block_data=block_data if is_blocked else None)
        
        # Form is active, show the submission form
        return render_template('form_response.html', 
                             form=form_copy, 
                             event=event_found,
                             form_id=form_id,
                             creator_info=creator_info,
                             is_blocked=is_blocked,
                             block_reason=block_reason if is_blocked else None,
                             block_data=block_data if is_blocked else None)
    else:
        # Form not found - show simple public page
        status_type = 'not_found'
        message = "The form you're looking for doesn't exist or has been removed."
        
        return render_template('form_not_found_public.html',
                             form_id=form_id,
                             status_type=status_type,
                             message=message)

@app.route('/test_resend_sdk')
def test_resend_sdk():
    """Test Resend SDK integration"""
    try:
        test_email = os.environ.get('MAIL_USERNAME', 'eventflow.app2026@gmail.com')
        
        success, message = send_email_simple(
            test_email,
            "✅ Resend SDK Test - EventFlow",
            """
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>🎉 Resend SDK Test Successful!</h2>
                <p>This email was sent using the <strong>official Resend Python SDK</strong>.</p>
                <p>Time: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                <p>Your email system is now ready for Render deployment!</p>
            </body>
            </html>
            """
        )
        
        return jsonify({
            'success': success,
            'message': message,
            'test_email': test_email,
            'resend_sdk_version': '2.19.0'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/check_env')
def check_env():
    """Check if environment variables are loaded"""
    import os
    
    debug_info = {
        'RESEND_API_KEY_in_env': 'RESEND_API_KEY' in os.environ,
        'RESEND_API_KEY_value': os.environ.get('RESEND_API_KEY', 'NOT SET'),
        'RESEND_API_KEY_length': len(os.environ.get('RESEND_API_KEY', '')) if os.environ.get('RESEND_API_KEY') else 0,
        'MAIL_DEFAULT_SENDER': os.environ.get('MAIL_DEFAULT_SENDER'),
        'python_dotenv_loaded': os.environ.get('DOTENV_LOADED', 'Unknown'),
        'current_directory': os.getcwd(),
        'env_file_exists': os.path.exists('.env')
    }
    
    return jsonify(debug_info)
    
@app.route('/admin/view_blocked_ips')
@login_required
@admin_required
def admin_view_blocked_ips():
    """View all blocked IPs"""
    try:
        blocked_ips = []
        ip_dir = 'data/ip_tracking'
        
        if os.path.exists(ip_dir):
            for filename in os.listdir(ip_dir):
                if filename.endswith('.json'):
                    with open(os.path.join(ip_dir, filename), 'r') as f:
                        data = json.load(f)
                    
                    if 'blocked_until' in data:
                        blocked_until = datetime.fromisoformat(data['blocked_until'])
                        now = datetime.now()
                        
                        if now < blocked_until:
                            # Extract form_id from filename
                            parts = filename.replace('.json', '').split('_')
                            form_id = '_'.join(parts[:-5])  # Remove IP parts
                            
                            blocked_ips.append({
                                'form_id': form_id,
                                'ip': data['ip'],
                                'blocked_until': blocked_until.isoformat(),
                                'reason': 'Rate limit exceeded',
                                'total_submissions': data.get('total_submissions', 0),
                                'fast_submissions': data.get('fast_submissions', 0),
                                'time_left': str(blocked_until - now).split('.')[0]
                            })
        
        return render_template('admin_blocked_ips.html',
                             page_title='Blocked IPs',
                             active_page='admin_blocked_ips',
                             blocked_ips=blocked_ips)
        
    except Exception as e:
        flash(f'Error loading blocked IPs: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/send_test_individual_email', methods=['POST'])
@login_required
@admin_required
def admin_send_test_individual_email():
    """Send test individual email"""
    try:
        data = request.json
        recipient_email = data.get('recipient_email')
        recipient_name = data.get('recipient_name', 'User')
        subject = data.get('subject')
        content = data.get('content')
        sender_name = data.get('sender_name')
        
        if not all([recipient_email, subject, content, sender_name]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Create HTML email
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .test-note {{ background: #fff3cd; padding: 15px; border-radius: 6px; margin: 20px 0; color: #856404; border-left: 4px solid #ffc107; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>📢 EventFlow Message</h2>
                </div>
                <div class="content">
                    <div class="test-note">
                        <strong>⚠️ TEST EMAIL:</strong> This is a test email sent to verify the format before sending the actual message.
                    </div>
                    {content.replace('\n', '<br>')}
                    <div class="footer">
                        <p>Sent by: <strong>{sender_name}</strong></p>
                        <p>This is a test message from EventFlow.</p>
                        <p><small>Recipient: {recipient_name} ({recipient_email})</small></p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email
        success, message = send_email_simple(recipient_email, subject, html_content)
        
        if success:
            log_message(f"Test individual email sent to {recipient_email}", "ADMIN")
            return jsonify({'success': True, 'message': 'Test email sent'})
        else:
            return jsonify({'success': False, 'error': message})
            
    except Exception as e:
        log_message(f"Error sending test individual email: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/send_individual_email', methods=['POST'])
@login_required
@admin_required
def admin_send_individual_email():
    """Send individual email to a user"""
    try:
        data = request.json
        recipient_email = data.get('recipient_email')
        recipient_name = data.get('recipient_name', 'User')
        recipient_id = data.get('recipient_id')
        subject = data.get('subject')
        content = data.get('content')
        sender_name = data.get('sender_name')
        
        if not all([recipient_email, subject, content, sender_name]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Replace variables in content
        personalized_content = content\
            .replace('{username}', recipient_name)\
            .replace('{email}', recipient_email)\
            .replace('{join_date}', data.get('join_date', ''))
        
        # Create HTML email
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .unsubscribe {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 11px; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>📢 EventFlow Message</h2>
                </div>
                <div class="content">
                    {personalized_content.replace('\n', '<br>')}
                    <div class="footer">
                        <p>Sent by: <strong>{sender_name}</strong></p>
                        <p>This is an automated message from EventFlow.</p>
                    </div>
                    <div class="unsubscribe">
                        <p>You received this email because you're registered with EventFlow.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email
        success, message = send_email_simple(recipient_email, subject, html_content)
        
        if success:
            # Log the email
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'sender': session.get('user_id'),
                'sender_name': session.get('username'),
                'recipient_email': recipient_email,
                'recipient_name': recipient_name,
                'recipient_id': recipient_id,
                'subject': subject,
                'status': 'sent',
                'type': 'individual'
            }
            
            # Save to email log
            email_log_file = 'data/email_individual_log.json'
            email_logs = []
            if os.path.exists(email_log_file):
                with open(email_log_file, 'r') as f:
                    email_logs = json.load(f)
            
            email_logs.append(log_entry)
            
            with open(email_log_file, 'w') as f:
                json.dump(email_logs, f, indent=2)
            
            log_message(f"Individual email sent to {recipient_email} ({recipient_name}) by {session.get('username')}", "ADMIN")
            return jsonify({'success': True, 'message': 'Email sent successfully'})
        else:
            log_message(f"Failed to send individual email to {recipient_email}: {message}", "ERROR")
            return jsonify({'success': False, 'error': message})
            
    except Exception as e:
        log_message(f"Error sending individual email: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/tools/migrate')
@login_required
@admin_required
def admin_migrate_tools():
    """Admin migration tools page"""
    return render_template('admin_migrate_tools.html',
                         page_title='Migration Tools',
                         active_page='admin_tools')
    
@app.route('/admin/unblock_ip/<ip>/<form_id>', methods=['POST'])
@login_required
@admin_required
def admin_unblock_ip(ip, form_id):
    """Unblock an IP address"""
    try:
        safe_ip = ip.replace('.', '_').replace(':', '_')
        ip_file = f'data/ip_tracking/{form_id}_{safe_ip}.json'
        
        if os.path.exists(ip_file):
            with open(ip_file, 'r') as f:
                data = json.load(f)
            
            # Remove block
            data.pop('blocked_until', None)
            data['fast_submissions'] = 0
            data['minute_count'] = 1
            
            with open(ip_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            log_message(f"IP {ip} unblocked for form {form_id} by admin", "ADMIN")
            return jsonify({'success': True, 'message': 'IP unblocked'})
        else:
            return jsonify({'success': False, 'error': 'IP record not found'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/account/blocked')
def account_blocked():
    """Direct access to account blocked page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('user_id')
    users = load_users()
    
    if user_id not in users:
        return redirect(url_for('login'))
    
    user_data = users[user_id]
    
    if not user_data.get('blocked', False):
        # User is not blocked, redirect to dashboard
        return redirect(url_for('dashboard'))
    
    # Show blocked page
    reason = user_data.get('blocked_reason', 'Violation of terms of service')
    blocked_at = user_data.get('blocked_at', '')
    
    # Calculate block duration
    block_until = 'permanent'
    if blocked_at:
        try:
            blocked_date = datetime.fromisoformat(blocked_at)
            block_duration = 7  # Default 7 days
            unblock_date = blocked_date + timedelta(days=block_duration)
            if datetime.now() < unblock_date:
                block_until = unblock_date.strftime('%Y-%m-%d %H:%M')
        except:
            pass
    
    support_email = os.environ.get('SUPPORT_EMAIL', MAIL_USERNAME)
    
    return render_template('account_blocked.html',
                         reason=reason,
                         blocked_at=blocked_at,
                         block_until=block_until,
                         support_email=support_email)

@app.route('/generate_response_pdf/<event_id>/<form_id>/<response_id>', methods=['POST'])
@login_required
def generate_response_pdf(event_id, form_id, response_id):
    try:
        data = request.json
        html_content = data.get('html_content', '')
        filename = data.get('filename', f'response_{response_id}.pdf')
        
        if not html_content:
            return jsonify({'error': 'No HTML content provided'}), 400
        
        # Generate PDF
        font_config = FontConfiguration()
        
        # Create PDF from HTML
        pdf = HTML(string=html_content).write_pdf(font_config=font_config)
        
        # Create response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        app.logger.error(f"PDF generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_verification_report/<event_id>/<form_id>')
def get_verification_report(event_id, form_id):
    """Get detailed verification report data"""
    try:
        event = get_event(event_id)
        if not event:
            return jsonify({"success": False, "error": "Event not found"}), 404
        
        form = next((f for f in event.forms if f.id == form_id), None)
        if not form:
            return jsonify({"success": False, "error": "Form not found"}), 404
        
        # Load responses
        responses = load_responses(event_id, form_id)
        
        # Load verification status
        verification_file = os.path.join(current_app.config['UPLOAD_FOLDER'], 
                                        event_id, form_id, 'verification_status.json')
        verification_status = {}
        
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
            except:
                verification_status = {}
        
        # Prepare report data
        report_data = []
        for i, response in enumerate(responses):
            response_id = response.get('Response ID', '')
            verification_info = verification_status.get(response_id, {})
            
            # Create entry number if not exists
            if 'Entry Number' not in response:
                response['Entry Number'] = i + 1
            
            report_data.append({
                'response': response,
                'verification': verification_info
            })
        
        return jsonify({
            "success": True,
            "report_data": report_data,
            "total_responses": len(responses)
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


    
@app.route('/admin/delete_form_completely/<form_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_form_completely(form_id):
    """Completely delete a form (admin only)"""
    try:
        # Find the form and its event
        form_found = False
        event_data = None
        event_id = None
        form_data = None
        
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
                        event = json.load(f)
                    
                    for form in event.get('forms', []):
                        if form['id'] == form_id:
                            form_found = True
                            event_data = event
                            event_id = event.get('id')
                            form_data = form
                            break
                    
                    if form_found:
                        break
                except:
                    continue
        
        if not form_found:
            return jsonify({'success': False, 'error': 'Form not found'})
        
        # Get creator information for notification
        creator_id = event_data.get('creator_id')
        creator_email = None
        creator_name = None
        
        users = load_users()
        if creator_id in users:
            creator_email = users[creator_id].get('email')
            creator_name = users[creator_id].get('username', 'User')
        
        # Remove form from event
        event_data['forms'] = [f for f in event_data['forms'] if f['id'] != form_id]
        
        # Save updated event
        save_event(event_data)
        
        # Delete form CSV file
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        if os.path.exists(csv_path):
            os.remove(csv_path)
        
        # Delete uploaded files
        upload_dir = f'static/uploads/events/{event_id}/{form_id}'
        if os.path.exists(upload_dir):
            import shutil
            shutil.rmtree(upload_dir)
        
        # Remove from reports
        reports = load_form_reports()
        if form_id in reports:
            reports.pop(form_id)
            save_form_reports(reports)
        
        # Remove from blocked forms
        blocked_forms = load_blocked_forms()
        if form_id in blocked_forms:
            blocked_forms.pop(form_id)
            save_blocked_forms(blocked_forms)
        
        # Delete notification file if exists
        notification_file = f'data/form_notifications/{form_id}.json'
        if os.path.exists(notification_file):
            os.remove(notification_file)
        
        # Send notification to creator
        if creator_email:
            subject = f"❌ Form Deleted: {form_data.get('title', 'Your Form')}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <div style="padding: 20px; font-family: Arial, sans-serif;">
                    <h2 style="color: #dc3545;">❌ Form Deleted by Admin</h2>
                    <p>Hello {creator_name},</p>
                    <p>Your form <strong>"{form_data.get('title', 'Unknown')}"</strong> has been permanently deleted by an administrator.</p>
                    
                    <div style="background: #fee2e2; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <p><strong>Reason:</strong> The form was found to violate EventFlow's Terms of Service.</p>
                        <p><strong>Action Taken:</strong> Permanent deletion</p>
                        <p><strong>Deleted At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <p><strong>⚠️ Important Information:</strong></p>
                    <ul>
                        <li>All form data, including responses, has been permanently deleted</li>
                        <li>The form URL is no longer accessible</li>
                        <li>If you believe this was a mistake, contact our support team</li>
                    </ul>
                    
                    <p>Please ensure your future forms comply with our community guidelines.</p>
                    
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6;">
                        <p style="font-size: 12px; color: #6c757d;">
                            This is an automated notification from EventFlow Moderation System.
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            send_email_simple(creator_email, subject, html_content)
        
        # Log the deletion
        log_message(f"Form {form_id} ('{form_data.get('title', 'Unknown')}') permanently deleted by admin: {session.get('username')}", "MODERATION")
        
        return jsonify({
            'success': True, 
            'message': 'Form permanently deleted',
            'form_title': form_data.get('title', 'Unknown'),
            'creator_notified': bool(creator_email)
        })
        
    except Exception as e:
        log_message(f"Error deleting form completely: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/admin/migrate_all_csvs', methods=['POST'])
@login_required
@admin_required
def admin_migrate_all_csvs():
    """Migrate all CSV files to include IP addresses"""
    try:
        migrated_count = 0
        failed_count = 0
        
        # Scan all events and forms
        for event_file in os.listdir('data/events'):
            if event_file.endswith('.json'):
                try:
                    with open(f'data/events/{event_file}', 'r') as f:
                        event = json.load(f)
                    
                    event_id = event.get('id')
                    
                    for form in event.get('forms', []):
                        form_id = form.get('id')
                        csv_path = f'data/events/{event_id}/{form_id}.csv'
                        
                        if os.path.exists(csv_path):
                            success = migrate_csv_to_include_ip(event_id, form_id)
                            if success:
                                migrated_count += 1
                            else:
                                failed_count += 1
                                
                except Exception as e:
                    log_message(f"Error processing {event_file}: {e}", "ERROR")
                    failed_count += 1
        
        log_message(f"Migration complete: {migrated_count} migrated, {failed_count} failed", "MIGRATION")
        
        return jsonify({
            'success': True,
            'message': f'Migrated {migrated_count} CSV files, {failed_count} failed',
            'migrated': migrated_count,
            'failed': failed_count
        })
        
    except Exception as e:
        log_message(f"Migration error: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/view_form/<event_id>/<form_id>')
@login_required
def view_form(event_id, form_id):
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    form = None
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form = f
            break
    
    if not form:
        flash('Form not found!', 'error')
        return redirect(url_for('dashboard'))
    
    form_url = url_for('show_form', form_id=form_id, _external=True)
    qr_code = generate_qr_code(form_url)
    
    # Load responses
    responses = []
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    if os.path.exists(csv_path):
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader, 1):
                # Add row number
                row['_row_number'] = i
                
                # Generate QR code for each response
                response_id = row.get('Response ID')
                if response_id:
                    qr_code_data, verification_url = generate_verification_qr(
                        event_id, form_id, response_id
                    )
                    
                    # Add QR code data to response
                    row['_qr_code'] = qr_code_data
                    row['_verification_url'] = verification_url
                    row['_response_id'] = response_id
                
                responses.append(row)
    
    # Get server statistics for the dashboard
    stats = get_server_statistics()
    
    return render_template('view_form.html',
                         event=event,
                         stats=stats,
                         form=form, 
                         form_url=form_url,
                         qr_code=qr_code,
                         responses=responses)



@app.route('/admin/mark_form_resolved/<form_id>', methods=['POST'])
@login_required
@admin_required
def admin_mark_form_resolved(form_id):
    """Mark form reports as resolved (no action needed)"""
    try:
        reports = load_form_reports()
        
        if form_id not in reports:
            return jsonify({'success': False, 'error': 'No reports found for this form'})
        
        # Get form info before removing
        form_info = reports[form_id]
        
        # Create a resolved entry in a separate file for audit trail
        resolved_file = 'data/reports/resolved_reports.json'
        resolved_data = {}
        
        if os.path.exists(resolved_file):
            with open(resolved_file, 'r', encoding='utf-8') as f:
                resolved_data = json.load(f)
        
        # Add to resolved reports
        resolved_data[form_id] = {
            **form_info,
            'resolved_at': datetime.now().isoformat(),
            'resolved_by': session['user_id'],
            'resolved_by_name': session.get('username', 'Admin'),
            'resolution': 'no_issue_found',
            'status': 'resolved'
        }
        
        # Save resolved reports
        with open(resolved_file, 'w', encoding='utf-8') as f:
            json.dump(resolved_data, f, indent=2, ensure_ascii=False)
        
        # Remove from active reports
        reports.pop(form_id)
        save_form_reports(reports)
        
        # Also remove from blocked forms if it was blocked
        blocked_forms = load_blocked_forms()
        if form_id in blocked_forms:
            blocked_forms.pop(form_id)
            save_blocked_forms(blocked_forms)
        
        # Send notification to creator if form was blocked
        creator_id = form_info.get('creator_id')
        creator_email = None
        users = load_users()
        
        if creator_id and creator_id in users:
            creator_email = users[creator_id].get('email')
        
        if creator_email:
            subject = f"✅ Form Review Complete: {form_info.get('form_title', 'Your Form')}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <div style="padding: 20px; font-family: Arial, sans-serif;">
                    <h2 style="color: #198754;">✅ Form Review Complete</h2>
                    <p>Hello,</p>
                    <p>Our moderation team has reviewed your form "<strong>{form_info.get('form_title', 'Unknown')}</strong>" and found no issues.</p>
                    
                    <div style="background: #d1fae5; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        <p><strong>Review Result:</strong> <span style="color: #198754;">NO ISSUES FOUND</span></p>
                        <p><strong>Status:</strong> Form is active and accessible</p>
                        <p><strong>Reviewed At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Resolution:</strong> Reports have been cleared</p>
                    </div>
                    
                    <p>Your form is fully accessible to users and all reports have been cleared.</p>
                    
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6;">
                        <p style="font-size: 12px; color: #6c757d;">
                            Thank you for using EventFlow. If you have any questions, please contact our support team.
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            send_email_simple(creator_email, subject, html_content)
        
        log_message(f"Form {form_id} marked as resolved by admin: {session.get('username')}", "MODERATION")
        return jsonify({
            'success': True, 
            'message': 'Form marked as resolved and removed from reports'
        })
        
    except Exception as e:
        log_message(f"Error marking form as resolved: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/get_resolved_reports')
@login_required
@admin_required
def admin_get_resolved_reports():
    """Get resolved reports for admin view"""
    try:
        resolved_file = 'data/reports/resolved_reports.json'
        resolved_reports = {}
        
        if os.path.exists(resolved_file):
            with open(resolved_file, 'r', encoding='utf-8') as f:
                resolved_reports = json.load(f)
        
        return jsonify({
            'success': True,
            'resolved_reports': resolved_reports,
            'total_resolved': len(resolved_reports)
        })
        
    except Exception as e:
        log_message(f"Error loading resolved reports: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/share_form/<event_id>/<form_id>', methods=['GET', 'POST'])
@login_required
def share_form(event_id, form_id):
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    form = None
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form = f
            break
    
    if not form:
        flash('Form not found!', 'error')
        return redirect(url_for('dashboard'))
    
    form_url = url_for('show_form', form_id=form_id, _external=True)
    qr_code = generate_qr_code(form_url)
    
    # Handle email sending
    if request.method == 'POST':
        if 'recipient_emails' in request.form:
            recipient_emails = request.form.get('recipient_emails', '')
            custom_message = request.form.get('custom_message', '')
            
            if not recipient_emails:
                flash('Please enter at least one email address.', 'error')
                return redirect(url_for('share_form', event_id=event_id, form_id=form_id))
            
            # Parse emails
            email_list = [email.strip() for email in recipient_emails.split(',') if email.strip()]
            valid_emails = []
            invalid_emails = []
            
            for email in email_list:
                if '@' in email and '.' in email and len(email) > 5:
                    valid_emails.append(email)
                else:
                    invalid_emails.append(email)
            
            if not valid_emails:
                flash('No valid email addresses found.', 'error')
                return redirect(url_for('share_form', event_id=event_id, form_id=form_id))
            
            if invalid_emails:
                flash(f'⚠️ {len(invalid_emails)} invalid email(s) ignored: {", ".join(invalid_emails[:3])}', 'warning')
            
            # Send emails
            try:
                results = send_emails_direct(
                    valid_emails,
                    form_url,
                    form['title'],
                    event['name'],
                    session['username'],
                    custom_message
                )
                
                # Count results
                sent_count = sum(1 for r in results if r['status'] == 'sent')
                failed_count = sum(1 for r in results if r['status'] == 'failed')
                invalid_count = sum(1 for r in results if r['status'] == 'invalid')
                
                # Show results
                if sent_count > 0:
                    flash(f'✅ {sent_count} email(s) sent successfully!', 'success')
                    
                if failed_count > 0:
                    flash(f'❌ {failed_count} email(s) failed to send. Check logs for details.', 'error')
                            
                if invalid_count > 0:
                    flash(f'⚠️ {invalid_count} email(s) were invalid format.', 'warning')
                
                # Save results for display
                session['last_email_results'] = results[:10]
                
            except Exception as e:
                error_msg = str(e)
                flash(f'❌ Error sending emails: {error_msg[:200]}', 'error')
            
            return redirect(url_for('share_form', event_id=event_id, form_id=form_id))
    
    # Get last results if available
    last_results = session.get('last_email_results', [])
    
    return render_template('share_form.html', 
                         event=event, 
                         form=form, 
                         form_url=form_url,
                         qr_code=qr_code,
                         last_results=last_results)



# ============================================================================
# ACCOUNT MANAGEMENT ROUTES (Block/Unblock)
# ============================================================================

@app.route('/admin/block_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_block_user(user_id):
    """Block a user account"""
    try:
        data = request.json
        reason = data.get('reason', 'Violation of terms of service')
        duration_days = data.get('duration_days', 7)
        notify_user = data.get('notify_user', True)
        
        if session.get('user_id') == user_id:
            return jsonify({'success': False, 'error': 'Cannot block your own account'})
        
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user_data = users[user_id]
        
        # Check if user is already blocked
        if user_data.get('blocked', False):
            return jsonify({'success': False, 'error': 'User is already blocked'})
        
        # Block the user
        users[user_id]['blocked'] = True
        users[user_id]['blocked_reason'] = reason
        users[user_id]['blocked_at'] = datetime.now().isoformat()
        users[user_id]['blocked_by'] = session['user_id']
        users[user_id]['blocked_by_name'] = session.get('username', 'Admin')
        users[user_id]['block_until'] = (datetime.now() + timedelta(days=duration_days)).isoformat() if duration_days > 0 else 'permanent'
        users[user_id]['block_duration_days'] = duration_days
        
        save_users(users)
        
        # Send notification email to user if requested
        if notify_user and user_data.get('email'):
            send_account_blocked_email(
                user_data['email'],
                user_data.get('username', 'User'),
                reason,
                duration_days,
                session.get('username', 'Admin')
            )
        
        # Log the action
        log_message(f"User {user_id} ({user_data.get('email')}) blocked by {session['user_id']}. Reason: {reason}", "ADMIN")
        
        # If user is currently logged in, invalidate their session
        # You might want to implement session invalidation logic here
        
        return jsonify({
            'success': True,
            'message': f'User {user_data.get("username", "Unknown")} has been blocked',
            'user_data': {
                'username': user_data.get('username'),
                'email': user_data.get('email'),
                'blocked': True,
                'blocked_at': users[user_id]['blocked_at'],
                'block_until': users[user_id]['block_until']
            }
        })
        
    except Exception as e:
        log_message(f"Error blocking user: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/unblock_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_unblock_user(user_id):
    """Unblock a user account"""
    try:
        data = request.json
        unblock_reason = data.get('reason', 'Block expired or manually removed')
        notify_user = data.get('notify_user', True)
        
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user_data = users[user_id]
        
        # Check if user is actually blocked
        if not user_data.get('blocked', False):
            return jsonify({'success': False, 'error': 'User is not blocked'})
        
        # Unblock the user
        users[user_id]['blocked'] = False
        users[user_id]['unblocked_at'] = datetime.now().isoformat()
        users[user_id]['unblocked_by'] = session['user_id']
        users[user_id]['unblocked_by_name'] = session.get('username', 'Admin')
        users[user_id]['unblock_reason'] = unblock_reason
        
        # Keep blocked history
        if 'block_history' not in users[user_id]:
            users[user_id]['block_history'] = []
        
        users[user_id]['block_history'].append({
            'blocked_at': user_data.get('blocked_at'),
            'blocked_by': user_data.get('blocked_by'),
            'blocked_reason': user_data.get('blocked_reason'),
            'block_duration': user_data.get('block_duration_days'),
            'unblocked_at': datetime.now().isoformat(),
            'unblocked_by': session['user_id'],
            'unblock_reason': unblock_reason
        })
        
        # Clear blocking fields
        users[user_id].pop('blocked_reason', None)
        users[user_id].pop('blocked_at', None)
        users[user_id].pop('blocked_by', None)
        users[user_id].pop('block_until', None)
        users[user_id].pop('block_duration_days', None)
        
        save_users(users)
        
        # Send notification email to user if requested
        if notify_user and user_data.get('email'):
            send_account_unblocked_email(
                user_data['email'],
                user_data.get('username', 'User'),
                unblock_reason,
                session.get('username', 'Admin')
            )
        
        # Log the action
        log_message(f"User {user_id} ({user_data.get('email')}) unblocked by {session['user_id']}", "ADMIN")
        
        return jsonify({
            'success': True,
            'message': f'User {user_data.get("username", "Unknown")} has been unblocked',
            'user_data': {
                'username': user_data.get('username'),
                'email': user_data.get('email'),
                'blocked': False,
                'unblocked_at': users[user_id]['unblocked_at']
            }
        })
        
    except Exception as e:
        log_message(f"Error unblocking user: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/get_blocked_users')
@login_required
@admin_required
def admin_get_blocked_users():
    """Get all blocked users"""
    try:
        users = load_users()
        
        blocked_users = []
        for user_id, user_data in users.items():
            if user_data.get('blocked', False):
                # Calculate time left if temporary block
                time_left = None
                if user_data.get('block_until') and user_data.get('block_until') != 'permanent':
                    try:
                        block_until = datetime.fromisoformat(user_data['block_until'])
                        now = datetime.now()
                        if block_until > now:
                            time_left = str(block_until - now).split('.')[0]
                        else:
                            time_left = "EXPIRED"
                    except:
                        time_left = "Unknown"
                
                blocked_users.append({
                    'user_id': user_id,
                    'username': user_data.get('username', 'Unknown'),
                    'email': user_data.get('email', ''),
                    'blocked_at': user_data.get('blocked_at', ''),
                    'blocked_by': user_data.get('blocked_by', ''),
                    'blocked_by_name': user_data.get('blocked_by_name', ''),
                    'blocked_reason': user_data.get('blocked_reason', ''),
                    'block_until': user_data.get('block_until', ''),
                    'block_duration_days': user_data.get('block_duration_days', 0),
                    'time_left': time_left,
                    'events_count': get_user_events_count(user_id),
                    'forms_count': get_user_forms_count(user_id)
                })
        
        # Sort by most recently blocked
        blocked_users.sort(key=lambda x: x.get('blocked_at', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'blocked_users': blocked_users,
            'total_blocked': len(blocked_users)
        })
        
    except Exception as e:
        log_message(f"Error getting blocked users: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/get_user_block_history/<user_id>')
@login_required
@admin_required
def admin_get_user_block_history(user_id):
    """Get block history for a user"""
    try:
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user_data = users[user_id]
        block_history = user_data.get('block_history', [])
        
        # Sort history by most recent
        block_history.sort(key=lambda x: x.get('blocked_at', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'block_history': block_history,
            'total_blocks': len(block_history),
            'currently_blocked': user_data.get('blocked', False)
        })
        
    except Exception as e:
        log_message(f"Error getting block history: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_block_history/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_block_history(user_id):
    """Delete block history for a user"""
    try:
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if 'block_history' in users[user_id]:
            history_count = len(users[user_id]['block_history'])
            users[user_id].pop('block_history', None)
            save_users(users)
            
            log_message(f"Block history cleared for user {user_id} by {session['user_id']}", "ADMIN")
            return jsonify({
                'success': True,
                'message': f'Cleared {history_count} block history entries'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'No block history found'
            })
        
    except Exception as e:
        log_message(f"Error deleting block history: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})


# ============================================================================
# FORM MANAGEMENT ROUTES
# ============================================================================

@app.route('/edit_form_page/<event_id>/<form_id>', methods=['GET', 'POST'])
@login_required
def edit_form_page(event_id, form_id):
    """Show edit form page AND handle form updates with IP tracking"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    # Get form data
    form = None
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form = f
            break
    
    if not form:
        flash('Form not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Handle POST request (form submission)
    if request.method == 'POST':
        form_title = request.form.get('form_title', 'Registration Form')
        form_description = request.form.get('form_description', '')
        questions = []
        
        # Get schedule data
        enable_schedule = 'enable_schedule' in request.form
        schedule = {}
        
        if enable_schedule:
            start_datetime = request.form.get('start_datetime')
            end_datetime = request.form.get('end_datetime')
            notify_on_end = 'notify_on_end' in request.form
            
            # Validate schedule if provided
            if start_datetime or end_datetime:
                # Get existing schedule safely
                form_schedule = form.get('schedule')
                if form_schedule is None:
                    form_schedule = {}
                
                schedule = {
                    'enabled': True,
                    'start_datetime': start_datetime,
                    'end_datetime': end_datetime,
                    'notify_on_end': notify_on_end,
                    'created_at': form_schedule.get('created_at', datetime.now().isoformat()),
                    'notification_sent': form_schedule.get('notification_sent', False),
                    'notification_sent_at': form_schedule.get('notification_sent_at'),
                    'response_count_at_end': form_schedule.get('response_count_at_end', 0)
                }
                
                # If notify_on_end is enabled and end_datetime exists, schedule notification
                if notify_on_end and end_datetime and not schedule.get('notification_sent'):
                    user_email = session.get('email')
                    username = session.get('username', 'User')
                    
                    schedule_form_notification(
                        event_id=event_id,
                        form_id=form_id,
                        form_title=form_title,
                        end_datetime_str=end_datetime,
                        event_name=event['name'],
                        user_id=session['user_id'],
                        user_email=user_email
                    )
        else:
            schedule = None
        
        # Process questions
        i = 0
        while f'question_{i}' in request.form:
            question_text = request.form.get(f'question_{i}')
            question_type = request.form.get(f'type_{i}', 'text')
            
            question = {
                'id': i,
                'text': question_text,
                'type': question_type,
                'required': request.form.get(f'required_{i}', 'off') == 'on'
            }
            
            # DEBUG: See what form data we're receiving
            debug_form_submission(request.form, i)
            
            if question_type in ['radio', 'checkbox', 'dropdown']:
                options = request.form.get(f'options_{i}', '').split(',')
                question['options'] = [opt.strip() for opt in options if opt.strip()]
            
            # Handle file upload specific settings
            if question_type == 'file':
                # CRITICAL: Use getlist() for checkboxes
                file_types = request.form.getlist(f'file_types_{i}[]')
                
                # Get max size with validation
                file_max_size = request.form.get(f'file_max_size_{i}', '16')
                if not file_max_size or not file_max_size.isdigit():
                    file_max_size = '16'
                
                # Get multiple files setting
                file_multiple = request.form.get(f'file_multiple_{i}', 'off') == 'on'
                
                # Debug output
                print(f"DEBUG EDIT: Saving file settings for question {i}:")
                print(f"  File types: {file_types}")
                print(f"  Max size: {file_max_size} MB")
                print(f"  Multiple: {file_multiple}")
                
                question['file_settings'] = {
                    'allowed_types': file_types,
                    'max_size_mb': int(file_max_size),
                    'multiple': file_multiple
                }
            
            questions.append(question)
            i += 1
        
        # Update form data
        form['title'] = form_title
        form['description'] = form_description
        form['questions'] = questions
        form['schedule'] = schedule if schedule else None
        
        # Find and update the form in the event
        for i, f in enumerate(event['forms']):
            if f['id'] == form_id:
                event['forms'][i] = form
                break
        
        # Save updated event
        save_event(event)
        
        # Migrate existing CSV to include IP Address if needed
        migrate_csv_to_include_ip(event_id, form_id)
        
        # VERIFICATION: Check what was saved
        print("\n" + "="*60)
        print("VERIFICATION: Checking saved data")
        print(f"Event ID: {event_id}")
        print(f"Form ID: {form_id}")
        print(f"Total questions saved: {len(questions)}")
        
        for idx, q in enumerate(questions):
            if q.get('type') == 'file':
                print(f"\n📁 Question {idx} file settings:")
                print(f"  Text: {q.get('text', 'No text')}")
                if 'file_settings' in q:
                    print(f"  Allowed types: {q['file_settings'].get('allowed_types', [])}")
                    print(f"  Max size: {q['file_settings'].get('max_size_mb', 16)} MB")
                    print(f"  Multiple: {q['file_settings'].get('multiple', False)}")
                else:
                    print(f"  ⚠️ NO file_settings key found!")
        print("="*60 + "\n")
        
        flash('Form updated successfully!', 'success')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    # For GET request, show the form
    return render_template('create_form.html', 
                         event=event, 
                         form=form,
                         event_id=event_id,
                         form_id=form_id,
                         is_edit_mode=True)

                   

@app.route('/view_pdf/<event_id>/<form_id>')
@login_required
def view_pdf(event_id, form_id):
    event = load_event(event_id)
    if not event:
        abort(404)
    
    # Find the specific form title
    form_title = "Unknown Form"
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form_title = f.get('title')
            break
            
    return render_template('view_pdf.html', 
                           event_id=event_id, 
                           form_id=form_id, 
                           event_name=event.get('name'), 
                           form_title=form_title)
                         
@app.route('/admin/mark_feedback_resolved/<feedback_id>', methods=['POST'])
@login_required
@admin_required
def admin_mark_feedback_resolved(feedback_id):
    """Mark feedback as resolved"""
    try:
        feedback_data = load_feedback()
        
        feedback_found = False
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                fb['status'] = 'resolved'
                fb['resolved_at'] = datetime.now().isoformat()
                fb['resolved_by'] = session['user_id']
                fb['resolved_by_name'] = session.get('username', 'Admin')
                fb['reviewed'] = True
                fb['reviewed_at'] = datetime.now().isoformat()
                feedback_found = True
                break
        
        if not feedback_found:
            return jsonify({'success': False, 'error': 'Feedback not found'})
        
        if save_feedback(feedback_data):
            log_message(f"Feedback {feedback_id} marked as resolved by admin: {session.get('username')}", "ADMIN")
            return jsonify({'success': True, 'message': 'Feedback marked as resolved'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        log_message(f"Error marking feedback as resolved: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/bulk_mark_feedback_resolved', methods=['POST'])
@login_required
@admin_required
def admin_bulk_mark_feedback_resolved():
    """Bulk mark feedback as resolved"""
    try:
        data = request.json
        feedback_ids = data.get('feedback_ids', [])
        
        if not feedback_ids:
            return jsonify({'success': False, 'error': 'No feedback IDs provided'})
        
        feedback_data = load_feedback()
        resolved_count = 0
        
        for fb in feedback_data:
            if fb['id'] in feedback_ids:
                fb['status'] = 'resolved'
                fb['resolved_at'] = datetime.now().isoformat()
                fb['resolved_by'] = session['user_id']
                fb['resolved_by_name'] = session.get('username', 'Admin')
                fb['reviewed'] = True
                fb['reviewed_at'] = datetime.now().isoformat()
                resolved_count += 1
        
        if save_feedback(feedback_data):
            log_message(f"Bulk marked {resolved_count} feedback items as resolved by admin", "ADMIN")
            return jsonify({
                'success': True,
                'message': f'{resolved_count} feedback item(s) marked as resolved',
                'resolved_count': resolved_count
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        log_message(f"Error in bulk mark feedback resolved: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/revoke_verification/<event_id>/<form_id>/<response_id>', methods=['POST'])
def revoke_verification(event_id, form_id, response_id):
    """Revoke a verification decision"""
    try:
        # Check if user is in volunteer mode or is admin
        current_user = None
        current_user_id = None
        
        if session.get('volunteer_mode'):
            current_user = session.get('volunteer_name')
            current_user_id = session.get('volunteer_code')
        elif session.get('user_id') == 'admin':
            current_user = session.get('username', 'Admin')
            current_user_id = session.get('user_id')
        else:
            return jsonify({
                'success': False, 
                'error': 'Unauthorized access'
            }), 401
        
        # Load verification status
        verification_file = f'static/uploads/events/{event_id}/{form_id}/verification_status.json'
        verification_status = {}
        
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
            except:
                verification_status = {}
        
        # Check if response exists in verification
        if response_id not in verification_status:
            return jsonify({
                'success': False, 
                'error': 'No verification record found'
            }), 404
        
        verification_data = verification_status[response_id]
        verified_by_id = verification_data.get('verified_by_id', '')
        
        # Check permissions: only original verifier or admin can revoke
        if current_user_id != 'admin' and current_user_id != verified_by_id:
            return jsonify({
                'success': False, 
                'error': 'Only the original verifier or admin can revoke this decision'
            }), 403
        
        # Archive the old verification
        archive_file = f'static/uploads/events/{event_id}/{form_id}/verification_archive.json'
        archive_data = {}
        
        if os.path.exists(archive_file):
            try:
                with open(archive_file, 'r') as f:
                    archive_data = json.load(f)
            except:
                archive_data = {}
        
        # Add to archive
        archive_entry = verification_data.copy()
        archive_entry['revoked_by'] = current_user
        archive_entry['revoked_by_id'] = current_user_id
        archive_entry['revoked_at'] = datetime.now().isoformat()
        
        if response_id not in archive_data:
            archive_data[response_id] = []
        archive_data[response_id].append(archive_entry)
        
        with open(archive_file, 'w') as f:
            json.dump(archive_data, f, indent=2, ensure_ascii=False)
        
        # Remove from active verification (set back to pending)
        verification_status.pop(response_id, None)
        
        # Save updated verification status
        with open(verification_file, 'w') as f:
            json.dump(verification_status, f, indent=2, ensure_ascii=False)
        
        log_message(f"Verification revoked: Response {response_id} by {current_user}", "VERIFICATION")
        
        return jsonify({
            'success': True,
            'message': 'Verification decision revoked successfully',
            'status': 'pending'
        })
        
    except Exception as e:
        log_message(f"Revoke verification error: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)}), 500
        
@app.route('/check_verification_status/<event_id>/<form_id>/<response_id>')
def check_verification_status(event_id, form_id, response_id):
    """Check verification status for a specific response"""
    try:
        verification_file = f'static/uploads/events/{event_id}/{form_id}/verification_status.json'
        verification_status = {}
        
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
            except:
                verification_status = {}
        
        verification_data = verification_status.get(response_id, {})
        
        return jsonify({
            'success': True,
            'status': verification_data.get('status', 'pending'),
            'verified_by': verification_data.get('verified_by', ''),
            'verified_by_id': verification_data.get('verified_by_id', ''),
            'timestamp': verification_data.get('timestamp', ''),
            'notes': verification_data.get('notes', '')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})        

@app.route('/verify_response/<event_id>/<form_id>/<response_id>')
def verify_response(event_id, form_id, response_id):
    """Verify a response via QR code - BLOCKED when already verified"""
    try:
        # Load event
        event = None
        event_file = f'data/events/{event_id}.json'
        if os.path.exists(event_file):
            with open(event_file, 'r') as f:
                event = json.load(f)
        
        if not event:
            return render_template('verify_error.html',
                                 message="Event not found or has been deleted",
                                 event={'name': 'Unknown Event'},
                                 form={'title': 'Unknown Form'},
                                 response_id=response_id,
                                 is_valid=False,
                                 timestamp='Unknown',
                                 current_time=datetime.now())
        
        # Find the form
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            return render_template('verify_error.html',
                                 message="Form not found or has been deleted",
                                 event=event,
                                 form={'title': 'Unknown Form'},
                                 response_id=response_id,
                                 is_valid=False,
                                 timestamp='Unknown',
                                 current_time=datetime.now())
        
        # Check verification status
        verification_file = f'static/uploads/events/{event_id}/{form_id}/verification_status.json'
        verification_status = {}
        
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
            except:
                verification_status = {}
        
        # Get verification data
        verification_data = verification_status.get(response_id, {})
        verification_status_value = verification_data.get('status', 'pending')
        
        # CRITICAL: Check if response is already verified (passed or declined)
        is_already_verified = verification_status_value in ['passed', 'declined']
        
        # Load response data
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        response = None
        timestamp = 'Unknown'
        entry_number = 0
        
        if os.path.exists(csv_path):
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader, 1):
                    if row.get('Response ID') == response_id:
                        response = row
                        timestamp = row.get('Timestamp', 'Unknown')
                        entry_number = i
                        break
        
        if not response:
            return render_template('verify_error.html',
                                 message="Response not found or has been deleted",
                                 event=event,
                                 form=form,
                                 response_id=response_id,
                                 is_valid=False,
                                 timestamp='Unknown',
                                 current_time=datetime.now())
        
        # Check if current user is in volunteer mode or is admin
        current_user = None
        current_user_id = None
        can_revoke = False
        
        if session.get('volunteer_mode'):
            current_user = session.get('volunteer_name')
            current_user_id = session.get('volunteer_code')
        elif session.get('user_id') == 'admin':
            current_user = session.get('username', 'Admin')
            current_user_id = session.get('user_id')
        
        # If response is already verified, check if user can revoke
        if is_already_verified:
            verified_by_id = verification_data.get('verified_by_id', '')
            
            # Check if current user can revoke (original verifier or admin)
            if current_user_id and verified_by_id and current_user_id == verified_by_id:
                can_revoke = True
            elif current_user_id == 'admin':  # Admin can always revoke
                can_revoke = True
            elif session.get('user_id') == event.get('creator_id'):  # Event creator can also revoke
                can_revoke = True
            
            # Show BLOCKED page for everyone except those who can revoke
            if not can_revoke:
                return render_template('verification_blocked.html',
                                     event=event,
                                     form=form,
                                     response=response,
                                     response_id=response_id,
                                     timestamp=timestamp,
                                     entry_number=entry_number,
                                     verification_status=verification_status_value,
                                     verified_by=verification_data.get('verified_by', ''),
                                     verification_time=verification_data.get('timestamp', ''),
                                     verification_notes=verification_data.get('notes', ''),
                                     is_valid=True,
                                     is_blocked=True,
                                     can_revoke=False,
                                     current_user=current_user,
                                     current_time=datetime.now())
        
        # Response is either: pending, OR verified but user can revoke
        return render_template('verify_response.html',
                             event=event,
                             form=form,
                             response=response,
                             response_id=response_id,
                             timestamp=timestamp,
                             entry_number=entry_number,
                             verification_status=verification_status_value,
                             verified_by=verification_data.get('verified_by', ''),
                             verification_time=verification_data.get('timestamp', ''),
                             verification_notes=verification_data.get('notes', ''),
                             is_valid=True,
                             is_blocked=is_already_verified,
                             can_revoke=can_revoke if is_already_verified else False,
                             current_user=current_user,
                             current_time=datetime.now())
        
    except Exception as e:
        print(f"Verification error: {e}")
        return render_template('verify_error.html',
                             event={'name': 'Error'},
                             form={'title': 'Error'},
                             response_id=response_id,
                             timestamp='Error',
                             is_valid=False,
                             is_blocked=False,
                             current_time=datetime.now())
# Helper function to generate QR code
def generate_verification_qr(event_id, form_id, response_id):
    """Generate QR code for response verification - FIXED VERSION"""
    try:
        # Get base URL from environment or use request
        base_url = os.environ.get('BASE_URL')
        if not base_url:
            # Try to get from current request
            try:
                base_url = request.host_url.rstrip('/')
            except:
                # Fallback to default
                base_url = 'https://overpotent-bianca-foamy.ngrok-free.dev'
        
        # Create verification URL
        verification_url = f"{base_url}/verify_response/{event_id}/{form_id}/{response_id}"
        
        # Generate QR code with EventFlow logo
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=2,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)
        
        # Create QR code image with blue color
        qr_img = qr.make_image(fill_color="#4a6cf7", back_color="white").convert('RGB')
        
        # Try to add logo
        logo_path = 'static/logo/icon.png'
        if os.path.exists(logo_path):
            try:
                from PIL import Image
                logo = Image.open(logo_path)
                
                # Calculate size
                qr_width, qr_height = qr_img.size
                logo_size = int(min(qr_width, qr_height) * 0.25)
                
                # Resize logo
                logo.thumbnail((logo_size, logo_size), Image.Resampling.LANCZOS)
                
                # Calculate position
                pos = ((qr_width - logo.size[0]) // 2, (qr_height - logo.size[1]) // 2)
                
                # Add logo
                qr_img.paste(logo, pos)
            except Exception as e:
                print(f"Logo error: {e}")
                # Continue without logo
        
        # Convert to base64
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG", optimize=True)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}", verification_url
        
    except Exception as e:
        print(f"QR generation error: {e}")
        # Create simple QR code as fallback
        try:
            import qrcode
            base_url = os.environ.get('BASE_URL', 'https://overpotent-bianca-foamy.ngrok-free.dev')
            verification_url = f"{base_url}/verify_response/{event_id}/{form_id}/{response_id}"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(verification_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            return f"data:image/png;base64,{img_str}", verification_url
        except:
            return None, ""

@app.route('/revoke_verification_status/<event_id>/<form_id>', methods=['POST'])
def revoke_verification_status(event_id, form_id):
    """Revoke a verification decision"""
    try:
        print(f"Revoking verification status for event {event_id}, form {form_id}")
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400
        
        response_id = data.get('response_id')
        
        if not response_id:
            return jsonify({"success": False, "error": "Missing response_id"}), 400
        
        # Use the global app variable
        upload_folder = app.config['UPLOAD_FOLDER']
        
        # Load existing verification status
        verification_file = os.path.join(upload_folder, event_id, form_id, 'verification_status.json')
        
        if not os.path.exists(verification_file):
            return jsonify({"success": False, "error": "No verification records found"}), 404
        
        with open(verification_file, 'r') as f:
            verification_status = json.load(f)
        
        # Check if response exists in verifications
        if response_id not in verification_status:
            return jsonify({
                "success": False, 
                "error": "Response not found in verifications",
                "available_ids": list(verification_status.keys())[:10]  # Show first 10 IDs for debugging
            }), 404
        
        # Get the current verification to preserve history
        current_verification = verification_status[response_id]
        
        # Update to pending status
        verification_status[response_id] = {
            'status': 'pending',
            'verified_by': '',
            'timestamp': datetime.now().isoformat(),
            'previous_status': current_verification.get('status'),
            'previous_verified_by': current_verification.get('verified_by'),
            'revoked_at': datetime.now().isoformat()
        }
        
        # Save updated verification status
        with open(verification_file, 'w') as f:
            json.dump(verification_status, f, indent=2)
        
        print(f"Revoked verification for response {response_id}")
        
        return jsonify({
            "success": True,
            "message": "Verification revoked successfully",
            "verification": verification_status[response_id],
            "previous_status": current_verification.get('status')
        })
        
    except Exception as e:
        print(f"Error revoking verification status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/verification_blocked/<event_id>/<form_id>/<response_id>')
def verification_blocked(event_id, form_id, response_id):
    """Show verification blocked page"""
    # Similar to verify_response but shows blocked page
    # You can reuse the same data fetching logic from verify_response
    return render_template('verification_blocked.html',
                         event=event,
                         form=form,
                         response_id=response_id,
                         verification_status=verification_status_value,
                         verified_by=verified_by,
                         current_time=datetime.now())

@app.route('/download_csv_with_ip/<event_id>/<form_id>')
@login_required
def download_csv_with_ip(event_id, form_id):
    """Download CSV with attendee IP addresses"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the form data from the event - forms is a LIST
    forms = event.get('forms', [])
    
    # BEST APPROACH: List comprehension + next() for efficiency
    form_data = next((f for f in forms if f.get('id') == form_id), None)
    
    if not form_data:
        flash('Form not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Ensure CSV has IP column
    migrate_csv_to_include_attendee_ip(event_id, form_id)
    
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    if not os.path.exists(csv_path):
        flash('No responses found!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    # Create safe filename
    event_name = event.get('name', 'Event').replace(' ', '_').replace('/', '_')
    form_title = form_data.get('title', 'Form').replace(' ', '_').replace('/', '_')
    filename = f"{event_name}_{form_title}_with_ip.csv"
    
    # Read CSV and serve as download
    with open(csv_path, 'r', encoding='utf-8') as f:
        csv_data = f.read()
    
    response = make_response(csv_data)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response

@app.template_filter('safe_lower')
def safe_lower_filter(value):
    """Safely convert string to lowercase, handling None values"""
    if value is None:
        return ''
    return str(value).lower()

# Use it in template:

@app.template_test('is_file_field')
def is_file_field(key):
    """Check if a key represents a file upload field, safely handling None."""
    if key is None:
        return False
    key_lower = str(key).lower()
    return any(term in key_lower for term in ['upload', 'file', 'photo', 'image', 'attachment'])


@app.route('/verify_by_code/<verification_code>')
def verify_by_code(verification_code):
    """Verify a response using verification code (for volunteer mode)"""
    try:
        # Look for the verification code in the database
        verification_file = f'data/verifications/{verification_code}.json'
        
        if not os.path.exists(verification_file):
            return render_template('verify_error.html',
                                 message="Invalid verification code",
                                 is_valid=False,
                                 current_time=datetime.now())
        
        with open(verification_file, 'r') as f:
            verification_data = json.load(f)
        
        # Check if code is expired (24 hours validity)
        created_at = datetime.fromisoformat(verification_data.get('created_at'))
        if (datetime.now() - created_at).total_seconds() > 24 * 3600:
            # Code expired
            os.remove(verification_file)  # Clean up expired code
            return render_template('verify_error.html',
                                 message="Verification code has expired",
                                 is_valid=False,
                                 current_time=datetime.now())
        
        # Get the actual response data
        event_id = verification_data.get('event_id')
        form_id = verification_data.get('form_id')
        response_id = verification_data.get('response_id')
        
        # Redirect to actual verification page
        return redirect(url_for('verify_response', 
                              event_id=event_id, 
                              form_id=form_id, 
                              response_id=response_id))
        
    except Exception as e:
        print(f"Verification code error: {e}")
        return render_template('verify_error.html',
                             message="Error processing verification code",
                             is_valid=False,
                             current_time=datetime.now())

@app.route('/volunteer_access/<event_id>/<form_id>')
def volunteer_access(event_id, form_id):
    """Generate volunteer access code and link"""
    try:
        # Generate a 16-character alphanumeric code
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        volunteer_code = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        # Create volunteer session data
        volunteer_data = {
            'code': volunteer_code,
            'event_id': event_id,
            'form_id': form_id,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=24)).isoformat(),
            'volunteer_name': None,
            'access_count': 0,
            'last_access': None
        }
        
        # Save volunteer code to file
        os.makedirs('data/volunteers', exist_ok=True)
        volunteer_file = f'data/volunteers/{volunteer_code}.json'
        
        with open(volunteer_file, 'w') as f:
            json.dump(volunteer_data, f, indent=2)
        
        # ALSO create a status file to track that volunteer mode is enabled
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        status_data = {
            'enabled': True,  # This is the key - volunteer mode is ENABLED
            'code': volunteer_code,
            'created_at': datetime.now().isoformat(),
            'event_id': event_id,
            'form_id': form_id,
            'created_by': 'admin'  # You might want to store which admin enabled it
        }
        
        with open(status_file, 'w') as f:
            json.dump(status_data, f, indent=2)
        
        # Generate access URL
        base_url = request.host_url.rstrip('/')
        access_url = f"{base_url}/volunteer_login/{volunteer_code}"
        
        return jsonify({
            'success': True,
            'code': volunteer_code,
            'access_url': access_url,
            'expires': volunteer_data['expires_at']
        })
        
    except Exception as e:
        print(f"Volunteer access error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/disable_volunteer_mode/<event_id>/<form_id>', methods=['POST'])
def disable_volunteer_mode(event_id, form_id):
    """Disable volunteer mode (called when admin toggles it off)"""
    try:
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                status_data = json.load(f)
            
            # Update status to disabled
            status_data['enabled'] = False
            status_data['disabled_at'] = datetime.now().isoformat()
            
            with open(status_file, 'w') as f:
                json.dump(status_data, f, indent=2)
        
        # Also clean up old volunteer session files (optional)
        volunteers_dir = 'data/volunteers'
        if os.path.exists(volunteers_dir):
            for filename in os.listdir(volunteers_dir):
                if filename.endswith('.json') and not filename.startswith('status_') and not filename.startswith('chat_'):
                    filepath = os.path.join(volunteers_dir, filename)
                    
                    with open(filepath, 'r') as f:
                        volunteer_data = json.load(f)
                    
                    # Check if this volunteer belongs to our event/form
                    if (volunteer_data.get('event_id') == event_id and 
                        volunteer_data.get('form_id') == form_id):
                        # Delete or mark as expired
                        volunteer_data['expires_at'] = datetime.now().isoformat()
                        with open(filepath, 'w') as f:
                            json.dump(volunteer_data, f, indent=2)
        
        return jsonify({'success': True, 'message': 'Volunteer mode disabled'})
        
    except Exception as e:
        print(f"Disable volunteer mode error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500        
        
@app.route('/volunteer_login/<volunteer_code>', methods=['GET', 'POST'])
def volunteer_login(volunteer_code):
    """Volunteer login page with code verification"""
    try:
        volunteer_file = f'data/volunteers/{volunteer_code}.json'
        
        if not os.path.exists(volunteer_file):
            return render_template('volunteer_error.html', 
                                 message="Invalid volunteer code")
        
        with open(volunteer_file, 'r') as f:
            volunteer_data = json.load(f)
        
        # Check if code is expired
        expires_at = datetime.fromisoformat(volunteer_data.get('expires_at'))
        if datetime.now() > expires_at:
            return render_template('volunteer_error.html',
                                 message="Volunteer code has expired")
        
        if request.method == 'POST':
            # Handle volunteer name submission
            volunteer_name = request.form.get('volunteer_name', '').strip()
            
            if not volunteer_name:
                return render_template('volunteer_login.html',
                                     volunteer_code=volunteer_code,
                                     error="Please enter your name")
            
            # Update volunteer data
            volunteer_data['volunteer_name'] = volunteer_name
            volunteer_data['access_count'] = volunteer_data.get('access_count', 0) + 1
            volunteer_data['last_access'] = datetime.now().isoformat()
            
            with open(volunteer_file, 'w') as f:
                json.dump(volunteer_data, f, indent=2)
            
            # Set session for volunteer
            session['volunteer_code'] = volunteer_code
            session['volunteer_name'] = volunteer_name
            session['event_id'] = volunteer_data['event_id']
            session['form_id'] = volunteer_data['form_id']
            session['volunteer_mode'] = True
            
            return redirect(url_for('volunteer_dashboard',
                                  event_id=volunteer_data['event_id'],
                                  form_id=volunteer_data['form_id']))
        
        return render_template('volunteer_login.html',
                             volunteer_code=volunteer_code)
        
    except Exception as e:
        print(f"Volunteer login error: {e}")
        return render_template('volunteer_error.html',
                             message="Error processing volunteer login")
@app.route('/volunteer_dashboard/<event_id>/<form_id>', defaults={'volunteer_name': None})
@app.route('/volunteer_dashboard/<event_id>/<form_id>/<volunteer_name>')
def volunteer_dashboard(event_id, form_id, volunteer_name=None):
    """Volunteer dashboard showing form responses with verification status"""
    
    # Determine volunteer name
    if volunteer_name is None:
        if not session.get('volunteer_mode') or not session.get('volunteer_name'):
            return redirect(url_for('volunteer_login', volunteer_code='invalid'))
        volunteer_name = session['volunteer_name']
    
    try:
        # Load event and form
        event_file = f'data/events/{event_id}.json'
        if not os.path.exists(event_file):
            return render_template('volunteer_error.html',
                                 message="Event not found")
        
        with open(event_file, 'r') as f:
            event = json.load(f)
        
        # Find the form
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            return render_template('volunteer_error.html',
                                 message="Form not found")
        
        # Load responses
        responses = []
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if os.path.exists(csv_path):
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader, 1):
                    row['Entry Number'] = i
                    response_id = row.get('Response ID', f'RES-{i:04d}')
                    row['Response ID'] = response_id
                    row['Verification ID'] = f"VER-{form_id[:8]}-{i}-{response_id[:8]}"
                    
                    # Get verification status for this response
                    verification_file = f'static/uploads/events/{event_id}/{form_id}/verification_status.json'
                    verification_status = {}
                    
                    if os.path.exists(verification_file):
                        try:
                            with open(verification_file, 'r') as f_ver:
                                verification_status = json.load(f_ver)
                        except:
                            verification_status = {}
                    
                    # Add verification info to response
                    if response_id in verification_status:
                        ver_data = verification_status[response_id]
                        row['verification_status'] = ver_data.get('status', 'pending')
                        row['verified_by'] = ver_data.get('verified_by', '')
                        row['verification_time'] = ver_data.get('timestamp', '')
                        row['verification_notes'] = ver_data.get('notes', '')
                        row['can_revoke'] = False
                        
                        # Check if current volunteer can revoke
                        current_volunteer_code = session.get('volunteer_code')
                        current_user_id = session.get('user_id')
                        
                        # Admin can always revoke
                        if current_user_id == 'admin':
                            row['can_revoke'] = True
                        # Original volunteer can revoke their own decision
                        elif ver_data.get('verified_by_id') == current_volunteer_code:
                            row['can_revoke'] = True
                    else:
                        row['verification_status'] = 'pending'
                        row['verified_by'] = ''
                        row['verification_time'] = ''
                        row['verification_notes'] = ''
                        row['can_revoke'] = False
                    
                    responses.append(row)
        
        # Load chat messages
        chat_file = f'data/volunteers/chat_{event_id}_{form_id}.json'
        messages = []
        
        if os.path.exists(chat_file):
            with open(chat_file, 'r') as f:
                messages = json.load(f)
        
        # Load complete verification status for JSON
        verification_file = f'static/uploads/events/{event_id}/{form_id}/verification_status.json'
        verification_status_json = {}
        
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status_json = json.load(f)
            except:
                verification_status_json = {}
        
        # Get volunteer stats
        stats = {
            'total_responses': len(responses),
            'pending_count': sum(1 for r in responses if r.get('verification_status') == 'pending'),
            'passed_count': sum(1 for r in responses if r.get('verification_status') == 'passed'),
            'declined_count': sum(1 for r in responses if r.get('verification_status') == 'declined')
        }
        
        return render_template('volunteer_dashboard.html',
                             event=event,
                             form=form,
                             responses=responses,
                             messages=messages,
                             volunteer_name=volunteer_name,
                             current_time=datetime.now(),
                             verification_status=json.dumps(verification_status_json),
                             stats=stats,
                             volunteer_code=session.get('volunteer_code'),
                             is_admin=session.get('user_id') == 'admin')
        
    except Exception as e:
        print(f"Volunteer dashboard error: {e}")
        return render_template('volunteer_error.html',
                             message="Error loading dashboard")

@app.route('/volunteer_chat/<event_id>/<form_id>', methods=['POST'])
def volunteer_chat(event_id, form_id):
    """Handle volunteer chat messages"""
    if not session.get('volunteer_mode') and not session.get('volunteer_name'):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        message = data.get('message', '').strip()
        volunteer_name = session.get('volunteer_name') or data.get('volunteer_name', 'Anonymous')
        
        if not message:
            return jsonify({'success': False, 'error': 'Empty message'}), 400
        
        chat_file = f'data/volunteers/chat_{event_id}_{form_id}.json'
        os.makedirs('data/volunteers', exist_ok=True)
        
        messages = []
        if os.path.exists(chat_file):
            with open(chat_file, 'r', encoding='utf-8') as f:
                messages = json.load(f)
        
        new_message = {
            'id': len(messages) + 1,
            'sender': volunteer_name,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'volunteer_code': session.get('volunteer_code', 'unknown')
        }
        
        messages.append(new_message)
        
        # Keep only last 100 messages
        if len(messages) > 100:
            messages = messages[-100:]
        
        with open(chat_file, 'w', encoding='utf-8') as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
        
        return jsonify({'success': True, 'message': new_message})
        
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
@app.route('/get_chat_messages/<event_id>/<form_id>')
def get_chat_messages(event_id, form_id):
    """Get chat messages for volunteers"""
    try:
        # Check if volunteer is logged in
        if not session.get('volunteer_mode'):
            return jsonify({
                'success': False,
                'error': 'Volunteer not logged in'
            }), 401
        
        chat_file = f'data/volunteers/chat_{event_id}_{form_id}.json'
        
        if os.path.exists(chat_file):
            with open(chat_file, 'r', encoding='utf-8') as f:
                messages = json.load(f)
        else:
            messages = []
        
        return jsonify({
            'success': True,
            'messages': messages
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e),
            'messages': []
        })
        
# ===== VOLUNTEER VERIFICATION API ROUTES =====

@app.route('/get_verification_status/<event_id>/<form_id>')
def get_verification_status(event_id, form_id):
    """Get current verification status for all responses"""
    try:
        print(f"Getting verification status for event {event_id}, form {form_id}")
        
        verification_file = os.path.join(current_app.config['UPLOAD_FOLDER'], 
                                        event_id, form_id, 'verification_status.json')
        
        verification_status = {}
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
                    print(f"Loaded {len(verification_status)} verification records")
            except Exception as e:
                print(f"Error loading verification file: {e}")
                verification_status = {}
        else:
            print(f"Verification file not found at {verification_file}")
        
        return jsonify({
            "success": True,
            "verifications": verification_status,
            "count": len(verification_status)
        })
        
    except Exception as e:
        print(f"Error getting verification status: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
        
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    
@app.route('/update_verification_status/<event_id>/<form_id>', methods=['POST'])
def update_verification_status(event_id, form_id):
    """Update verification status for a response - prevents re-verification"""
    try:
        print(f"Updating verification status for event {event_id}, form {form_id}")
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400
        
        response_id = data.get('response_id')
        status = data.get('status')
        verified_by = data.get('verified_by')
        
        print(f"Received data: response_id={response_id}, status={status}, verified_by={verified_by}")
        
        if not response_id:
            return jsonify({"success": False, "error": "Missing response_id"}), 400
        if not status:
            return jsonify({"success": False, "error": "Missing status"}), 400
        if not verified_by:
            return jsonify({"success": False, "error": "Missing verified_by"}), 400
        
        # Validate status
        if status not in ['passed', 'declined', 'pending']:
            return jsonify({"success": False, "error": f"Invalid status: {status}. Must be 'passed', 'declined', or 'pending'"}), 400
        
        # Ensure event directory exists
        event_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], event_id, form_id)
        os.makedirs(event_dir, exist_ok=True)
        
        # Load existing verification status
        verification_file = os.path.join(event_dir, 'verification_status.json')
        print(f"Verification file path: {verification_file}")
        
        verification_status = {}
        if os.path.exists(verification_file):
            try:
                with open(verification_file, 'r') as f:
                    verification_status = json.load(f)
                    print(f"Loaded {len(verification_status)} existing verification records")
            except Exception as e:
                print(f"Error loading verification file: {e}")
                verification_status = {}
        else:
            print(f"Verification file does not exist, creating new one at {verification_file}")
        
        # ===== CRITICAL: CHECK IF ALREADY VERIFIED =====
        # Check if already verified by someone else
        existing_status = verification_status.get(response_id, {})
        current_status = existing_status.get('status')
        
        # If already passed or declined, block further changes
        if current_status in ['passed', 'declined']:
            return jsonify({
                'success': False, 
                'error': 'Already verified by another volunteer',
                'blocked': True,  # Frontend can use this to block UI
                'status': current_status,
                'verified_by': existing_status.get('verified_by'),
                'timestamp': existing_status.get('timestamp')
            }), 403
        
        # ===== ALLOW PENDING TO BE CHANGED =====
        # "pending" can be changed to "passed" or "declined"
        # "passed"/"declined" cannot be changed (blocked above)
        
        # Update verification status
        previous_status = current_status or 'pending'
        verification_status[response_id] = {
            'status': status,
            'verified_by': verified_by,
            'timestamp': datetime.now().isoformat(),
            'previous_status': previous_status,
            'verified_by_id': data.get('verified_by_id', '')  # From first function
        }
        
        print(f"Updating response {response_id} from {previous_status} to {status} by {verified_by}")
        
        # Save updated verification status
        try:
            with open(verification_file, 'w') as f:
                json.dump(verification_status, f, indent=2)
            print(f"Successfully saved verification status to {verification_file}")
        except Exception as e:
            print(f"Error saving verification file: {e}")
            return jsonify({"success": False, "error": f"Failed to save verification status: {str(e)}"}), 500
        
        # Add to chat log for volunteer communication
        try:
            chat_file = os.path.join(event_dir, 'volunteer_chat.json')
            chat_data = {'messages': []}
            
            if os.path.exists(chat_file):
                with open(chat_file, 'r') as f:
                    chat_data = json.load(f)
            
            # Find participant name for chat message
            participant_name = "Participant"
            csv_path = os.path.join(current_app.config['UPLOAD_FOLDER'], event_id, f"{form_id}.csv")
            
            if os.path.exists(csv_path):
                import csv
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get('Response ID') == response_id:
                            participant_name = row.get('Name') or row.get('Full Name') or 'Participant'
                            break
            
            # Add system message
            system_message = {
                'id': str(int(time.time() * 1000)),
                'sender': 'System',
                'message': f'{verified_by} marked "{participant_name}" as {status.upper()}',
                'timestamp': datetime.now().isoformat(),
                'type': 'verification'
            }
            
            chat_data.setdefault('messages', []).append(system_message)
            
            # Keep only last 100 messages
            if len(chat_data['messages']) > 100:
                chat_data['messages'] = chat_data['messages'][-100:]
            
            with open(chat_file, 'w') as f:
                json.dump(chat_data, f, indent=2)
                
        except Exception as e:
            print(f"Error updating chat log: {e}")
            # Don't fail the whole request if chat update fails
        
        return jsonify({
            "success": True,
            "message": f"Status updated to {status}",
            "verification": verification_status[response_id],
            "total_verified": len([v for v in verification_status.values() if v['status'] in ['passed', 'declined']]),
            "final_decision": True if status in ['passed', 'declined'] else False
        })
        
    except Exception as e:
        print(f"Error updating verification status: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500
@app.route('/get_verification_updates/<event_id>/<form_id>')
def get_verification_updates(event_id, form_id):
    """Get recent verification updates"""
    try:
        # Check if volunteer is logged in
        if not session.get('volunteer_mode'):
            return jsonify({
                'success': False,
                'error': 'Volunteer not logged in'
            }), 401
        
        update_file = f'data/volunteers/updates_{event_id}_{form_id}.json'
        updates = []
        
        if os.path.exists(update_file):
            with open(update_file, 'r', encoding='utf-8') as f:
                updates = json.load(f)
        
        return jsonify({
            'success': True,
            'updates': updates
        })
        
    except Exception as e:
        print(f"Error loading verification updates: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'updates': []
        })        
        

@app.route('/volunteer_logout', methods=['POST'])
def volunteer_logout():
    """Handle volunteer logout"""
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        form_id = data.get('form_id')
        volunteer_name = data.get('volunteer_name')
        
        if not all([event_id, form_id, volunteer_name]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Find and update the volunteer session
        volunteer_files = [f for f in os.listdir('data/volunteers') if f.endswith('.json')]
        
        for filename in volunteer_files:
            if filename.startswith('chat_') or filename.startswith('status_'):
                continue
                
            try:
                with open(f'data/volunteers/{filename}', 'r') as f:
                    volunteer_data = json.load(f)
                
                if (volunteer_data.get('event_id') == event_id and 
                    volunteer_data.get('form_id') == form_id and
                    volunteer_data.get('volunteer_name') == volunteer_name):
                    
                    # Mark as logged out
                    volunteer_data['logged_out'] = True
                    volunteer_data['logged_out_at'] = datetime.now().isoformat()
                    
                    with open(f'data/volunteers/{filename}', 'w') as f:
                        json.dump(volunteer_data, f, indent=2)
                    
                    break
            except:
                continue
        
        # Clear session
        session.pop('volunteer_mode', None)
        session.pop('volunteer_name', None)
        session.pop('volunteer_code', None)
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        print(f"Volunteer logout error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500 

@app.route('/check_volunteer_session/<event_id>/<form_id>')
def check_volunteer_session(event_id, form_id):
    """Check if volunteer mode is enabled (ADMIN USE ONLY - should NOT depend on volunteer logins)"""
    try:
        # FIRST: Check if volunteer mode is enabled in a status file
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        
        volunteer_mode_enabled = False
        current_code = None
        
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                status_data = json.load(f)
                volunteer_mode_enabled = status_data.get('enabled', False)
                current_code = status_data.get('code')
        else:
            # If no status file exists, check if there are any volunteer files
            # This is for backward compatibility
            volunteers_dir = 'data/volunteers'
            if os.path.exists(volunteers_dir):
                for filename in os.listdir(volunteers_dir):
                    if filename.endswith('.json') and not filename.startswith('status_') and not filename.startswith('chat_'):
                        filepath = os.path.join(volunteers_dir, filename)
                        
                        with open(filepath, 'r') as f:
                            volunteer_data = json.load(f)
                        
                        # Check if this volunteer belongs to our event/form
                        if (volunteer_data.get('event_id') == event_id and 
                            volunteer_data.get('form_id') == form_id):
                            
                            # Check if not expired
                            expires_at = datetime.fromisoformat(volunteer_data.get('expires_at', datetime.now().isoformat()))
                            if datetime.now() <= expires_at:
                                volunteer_mode_enabled = True
                                current_code = volunteer_data.get('code')
                                break
        
        return jsonify({
            'active': volunteer_mode_enabled,  # This should be TRUE if admin enabled it
            'code': current_code
        })
        
    except Exception as e:
        print(f"Session check error: {e}")
        return jsonify({'active': False, 'error': str(e)}), 500

@app.route('/check_volunteer_dashboard_status/<event_id>/<form_id>/<volunteer_name>')
def check_volunteer_dashboard_status(event_id, form_id, volunteer_name):
    """Check if volunteer mode is still active for dashboard"""
    try:
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        
        if not os.path.exists(status_file):
            # Status file doesn't exist, session is ended
            return jsonify({
                'active': False,
                'message': 'Volunteer mode has been disabled by the administrator.'
            })
        
        with open(status_file, 'r') as f:
            status_data = json.load(f)
        
        if status_data.get('enabled') == False:
            # Volunteer mode is disabled
            return jsonify({
                'active': False,
                'message': 'Volunteer mode has been disabled by the administrator.'
            })
        
        # Check if the volunteer's session file exists
        volunteer_files = [f for f in os.listdir('data/volunteers') if f.endswith('.json')]
        volunteer_found = False
        
        for filename in volunteer_files:
            if filename.startswith('chat_') or filename.startswith('status_'):
                continue
                
            try:
                with open(f'data/volunteers/{filename}', 'r') as f:
                    volunteer_data = json.load(f)
                
                if (volunteer_data.get('event_id') == event_id and 
                    volunteer_data.get('form_id') == form_id and
                    volunteer_data.get('volunteer_name') == volunteer_name):
                    
                    # Check if session is expired
                    expires_at = datetime.fromisoformat(volunteer_data.get('expires_at'))
                    if datetime.now() > expires_at:
                        return jsonify({
                            'active': False,
                            'message': 'Your volunteer session has expired.'
                        })
                    
                    volunteer_found = True
                    break
            except:
                continue
        
        if not volunteer_found:
            return jsonify({
                'active': False,
                'message': 'Your volunteer session was not found or has been terminated.'
            })
        
        # All checks passed, session is active
        return jsonify({
            'active': True,
            'enabled': status_data.get('enabled', False),
            'message': 'Volunteer session is active.'
        })
        
    except Exception as e:
        print(f"Error checking volunteer status: {e}")
        return jsonify({
            'active': False,
            'message': 'Error checking session status.'
        })

@app.route('/volunteer_heartbeat/<event_id>/<form_id>/<volunteer_name>', methods=['POST'])
def volunteer_heartbeat_update(event_id, form_id, volunteer_name):
    """Update volunteer's last active time"""
    try:
        # Try to find volunteer file
        volunteers_dir = 'data/volunteers'
        if os.path.exists(volunteers_dir):
            for filename in os.listdir(volunteers_dir):
                if filename.endswith('.json') and not filename.startswith('status_') and not filename.startswith('chat_'):
                    filepath = os.path.join(volunteers_dir, filename)
                    
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    if (data.get('event_id') == event_id and 
                        data.get('form_id') == form_id and
                        data.get('volunteer_name') == volunteer_name):
                        
                        # Update last active time
                        data['last_active'] = datetime.now().isoformat()
                        
                        with open(filepath, 'w') as f:
                            json.dump(data, f, indent=2)
                        
                        print(f"✅ Updated heartbeat for {volunteer_name}")
                        return jsonify({'success': True})
        
        # If no file found, create one
        volunteer_file = f'data/volunteers/volunteer_{event_id}_{form_id}_{volunteer_name}.json'
        volunteer_data = {
            'volunteer_name': volunteer_name,
            'event_id': event_id,
            'form_id': form_id,
            'created_at': datetime.now().isoformat(),
            'last_active': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=24)).isoformat()
        }
        
        os.makedirs('data/volunteers', exist_ok=True)
        with open(volunteer_file, 'w') as f:
            json.dump(volunteer_data, f, indent=2)
        
        print(f"✅ Created new volunteer file for {volunteer_name}")
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"❌ Heartbeat error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/check_volunteer_mode_status/<event_id>/<form_id>')
def check_volunteer_mode_status(event_id, form_id):
    """Check if volunteer mode is enabled by admin"""
    try:
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                status_data = json.load(f)
            
            return jsonify({
                'enabled': status_data.get('enabled', False),
                'code': status_data.get('code'),
                'created_at': status_data.get('created_at'),
                'status': 'active'
            })
        else:
            return jsonify({
                'enabled': False,
                'status': 'disabled'
            })
        
    except Exception as e:
        print(f"Volunteer mode status check error: {e}")
        return jsonify({
            'enabled': False,
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/check_volunteer_session_status/<event_id>/<form_id>/<volunteer_name>')
def check_volunteer_session_status(event_id, form_id, volunteer_name):
    """Check if a specific volunteer session is still active"""
    try:
        print(f"Checking volunteer session for {volunteer_name} on form {form_id}")
        
        # 1. First check if volunteer mode is enabled
        status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
        if not os.path.exists(status_file):
            return jsonify({
                'active': False,
                'message': 'Volunteer mode is not enabled.'
            })
        
        with open(status_file, 'r') as f:
            status_data = json.load(f)
        
        if not status_data.get('enabled', False):
            return jsonify({
                'active': False,
                'message': 'Volunteer mode has been disabled.'
            })
        
        # 2. Check ALL volunteer files to find this volunteer
        volunteers_dir = 'data/volunteers'
        volunteer_found = False
        volunteer_data = None
        
        if os.path.exists(volunteers_dir):
            for filename in os.listdir(volunteers_dir):
                if filename.endswith('.json') and not filename.startswith('status_') and not filename.startswith('chat_'):
                    filepath = os.path.join(volunteers_dir, filename)
                    
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    if (data.get('event_id') == event_id and 
                        data.get('form_id') == form_id and
                        data.get('volunteer_name') == volunteer_name):
                        
                        volunteer_found = True
                        volunteer_data = data
                        break
        
        if not volunteer_found:
            return jsonify({
                'active': False,
                'message': 'Volunteer not found. Please log in again.'
            })
        
        # 3. Check if volunteer code is expired
        expires_at = datetime.fromisoformat(volunteer_data.get('expires_at', datetime.now().isoformat()))
        if datetime.now() > expires_at:
            return jsonify({
                'active': False,
                'message': 'Your volunteer session has expired.'
            })
        
        # 4. Check if the current code matches the status file code
        current_code = status_data.get('code')
        volunteer_code = volunteer_data.get('code')
        
        if current_code and volunteer_code and current_code != volunteer_code:
            return jsonify({
                'active': False,
                'message': 'The volunteer access code has been changed.'
            })
        
        # Session is ACTIVE!
        return jsonify({
            'active': True,
            'message': 'Session is active',
            'expires_at': expires_at.isoformat(),
            'volunteer_name': volunteer_name
        })
        
    except Exception as e:
        print(f"Volunteer session status check error: {e}")
        # On error, default to active so volunteers aren't kicked out
        return jsonify({
            'active': True,
            'message': 'Session check error, continuing...',
            'error': str(e)
        })        

@app.route('/debug_volunteer_status/<event_id>/<form_id>/<volunteer_name>')
def debug_volunteer_status(event_id, form_id, volunteer_name):
    """Debug endpoint to see volunteer status"""
    print(f"\n🔍 DEBUG Volunteer Status Check:")
    print(f"Event ID: {event_id}")
    print(f"Form ID: {form_id}")
    print(f"Volunteer Name: {volunteer_name}")
    
    # Check status file
    status_file = f'data/volunteers/status_{event_id}_{form_id}.json'
    print(f"Status file exists: {os.path.exists(status_file)}")
    
    if os.path.exists(status_file):
        with open(status_file, 'r') as f:
            status_data = json.load(f)
        print(f"Status data: {json.dumps(status_data, indent=2)}")
    
    # Check all volunteer files
    volunteers_dir = 'data/volunteers'
    print(f"\n📁 Volunteers directory exists: {os.path.exists(volunteers_dir)}")
    
    if os.path.exists(volunteers_dir):
        print("📋 All volunteer files:")
        for filename in os.listdir(volunteers_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(volunteers_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    matches = (data.get('event_id') == event_id and 
                              data.get('form_id') == form_id)
                    
                    print(f"\n  File: {filename}")
                    print(f"  Matches event/form: {matches}")
                    print(f"  Volunteer name: {data.get('volunteer_name')}")
                    print(f"  Code: {data.get('code')}")
                    print(f"  Expires at: {data.get('expires_at')}")
                    
                    if matches and data.get('volunteer_name') == volunteer_name:
                        expires_at = datetime.fromisoformat(data.get('expires_at', datetime.now().isoformat()))
                        is_expired = datetime.now() > expires_at
                        print(f"  ⚠️  EXPIRED: {is_expired}")
                        
                except Exception as e:
                    print(f"  Error reading {filename}: {e}")
    
    return jsonify({
        'message': 'Check server console for debug info'
    })
        
@app.route('/notify_volunteers_session_end/<event_id>/<form_id>', methods=['POST'])
def notify_volunteers_session_end(event_id, form_id):
    """Notify volunteers that session has ended"""
    try:
        data = request.json
        message = data.get('message', 'Volunteer mode has been disabled by the administrator.')
        
        # Add to chat
        chat_file = f'data/volunteers/chat_{event_id}_{form_id}.json'
        chat_messages = []
        
        if os.path.exists(chat_file):
            with open(chat_file, 'r') as f:
                chat_messages = json.load(f)
        
        chat_messages.append({
            'id': len(chat_messages) + 1,
            'sender': 'System',
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'type': 'system'
        })
        
        with open(chat_file, 'w') as f:
            json.dump(chat_messages, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': 'Volunteers notified'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'volunteer_dashboard'
    })

def notify_volunteers_of_verification(event_id, form_id, response_id, status, verified_by):
    """Notify all volunteers about verification update"""
    try:
        # Store notification for volunteers to check
        notification_file = f'data/notifications/{event_id}_{form_id}_verifications.json'
        os.makedirs(os.path.dirname(notification_file), exist_ok=True)
        
        notifications = []
        if os.path.exists(notification_file):
            with open(notification_file, 'r') as f:
                notifications = json.load(f)
        
        # Add new notification
        notifications.append({
            'response_id': response_id,
            'status': status,
            'verified_by': verified_by,
            'timestamp': datetime.now().isoformat(),
            'type': 'verification_update'
        })
        
        # Keep only last 100 notifications
        if len(notifications) > 100:
            notifications = notifications[-100:]
        
        with open(notification_file, 'w') as f:
            json.dump(notifications, f, indent=2)
            
    except Exception as e:
        print(f"Notification error: {e}")

@app.route('/end_volunteer_session/<event_id>/<form_id>', methods=['POST'])
def end_volunteer_session(event_id, form_id):
    """End a specific volunteer session"""
    try:
        data = request.get_json()
        volunteer_name = data.get('volunteer_name')
        reason = data.get('reason', 'Session ended by administrator')
        
        if not volunteer_name:
            return jsonify({'success': False, 'error': 'No volunteer name provided'})
        
        # Delete volunteer session file
        volunteer_file = f'data/volunteers/{event_id}_{form_id}_{volunteer_name}.json'
        
        if os.path.exists(volunteer_file):
            os.remove(volunteer_file)
            
            # Create notification file for the volunteer
            notification_file = f'data/notifications/{event_id}_{form_id}_{volunteer_name}_session_end.json'
            os.makedirs(os.path.dirname(notification_file), exist_ok=True)
            
            with open(notification_file, 'w') as f:
                json.dump({
                    'event_id': event_id,
                    'form_id': form_id,
                    'volunteer_name': volunteer_name,
                    'reason': reason,
                    'ended_at': datetime.now().isoformat(),
                    'ended_by': session.get('username', 'administrator')
                }, f, indent=2)
            
            return jsonify({'success': True, 'message': f'Session ended for {volunteer_name}'})
        else:
            return jsonify({'success': False, 'message': 'Session not found'})
            
    except Exception as e:
        print(f"End volunteer session error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/end_all_volunteer_sessions/<event_id>/<form_id>', methods=['POST'])
def end_all_volunteer_sessions(event_id, form_id):
    """End all volunteer sessions for this event/form"""
    try:
        data = request.get_json()
        reason = data.get('reason', 'Volunteer mode disabled by administrator')
        
        volunteers_dir = 'data/volunteers'
        ended_sessions = []
        
        if os.path.exists(volunteers_dir):
            for filename in os.listdir(volunteers_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(volunteers_dir, filename)
                    
                    # Check if this file belongs to our event/form
                    if f"{event_id}_{form_id}" in filename:
                        with open(filepath, 'r') as f:
                            volunteer_data = json.load(f)
                        
                        volunteer_name = volunteer_data.get('volunteer_name')
                        
                        # Create notification for this volunteer
                        notification_file = f'data/notifications/{event_id}_{form_id}_{volunteer_name}_session_end.json'
                        os.makedirs(os.path.dirname(notification_file), exist_ok=True)
                        
                        with open(notification_file, 'w') as f:
                            json.dump({
                                'event_id': event_id,
                                'form_id': form_id,
                                'volunteer_name': volunteer_name,
                                'reason': reason,
                                'ended_at': datetime.now().isoformat(),
                                'ended_by': session.get('username', 'administrator')
                            }, f, indent=2)
                        
                        ended_sessions.append(volunteer_name)
            
            return jsonify({
                'success': True, 
                'message': f'Ended {len(ended_sessions)} volunteer sessions',
                'ended_sessions': ended_sessions
            })
        else:
            return jsonify({'success': True, 'message': 'No active sessions found'})
            
    except Exception as e:
        print(f"End all volunteer sessions error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('connect', namespace='/ws/volunteer')
def handle_volunteer_connect():
    print('Volunteer WebSocket connected')
    
@socketio.on('disconnect', namespace='/ws/volunteer')
def handle_volunteer_disconnect():
    print('Volunteer WebSocket disconnected')

@socketio.on('join', namespace='/ws/volunteer')
def handle_volunteer_join(data):
    event_id = data.get('event_id')
    form_id = data.get('form_id')
    volunteer_name = data.get('volunteer_name')
    
    if all([event_id, form_id, volunteer_name]):
        room = f'{event_id}_{form_id}_{volunteer_name}'
        join_room(room)
        print(f'Volunteer {volunteer_name} joined room {room}')
        
        # Check for pending session end notifications
        notification_file = f'data/notifications/{event_id}_{form_id}_{volunteer_name}_session_end.json'
        if os.path.exists(notification_file):
            with open(notification_file, 'r') as f:
                notification = json.load(f)
            
            emit('session_ended', {
                'message': notification.get('reason', 'Your session has ended'),
                'ended_at': notification.get('ended_at')
            }, room=room)
            
            # Delete notification file after sending
            os.remove(notification_file)
        
@app.route('/get_active_volunteers/<event_id>/<form_id>')
def get_active_volunteers(event_id, form_id):
    """Get list of active volunteers"""
    try:
        volunteers = []
        total_accesses = 0
        last_access = None
        
        # Check volunteer directory
        if os.path.exists('data/volunteers'):
            for filename in os.listdir('data/volunteers'):
                if filename.endswith('.json') and not filename.startswith('chat_') and not filename.startswith('status_'):
                    filepath = os.path.join('data/volunteers', filename)
                    
                    try:
                        with open(filepath, 'r') as f:
                            volunteer_data = json.load(f)
                        
                        # Check if this volunteer belongs to our event/form
                        if (volunteer_data.get('event_id') == event_id and 
                            volunteer_data.get('form_id') == form_id):
                            
                            # Check if not expired
                            expires_at = datetime.fromisoformat(volunteer_data.get('expires_at', datetime.now().isoformat()))
                            is_expired = datetime.now() > expires_at
                            
                            if not is_expired and volunteer_data.get('volunteer_name'):
                                volunteers.append({
                                    'volunteer_name': volunteer_data.get('volunteer_name'),
                                    'code': volunteer_data.get('code', ''),
                                    'created_at': volunteer_data.get('created_at', ''),
                                    'last_access': volunteer_data.get('last_access'),
                                    'access_count': volunteer_data.get('access_count', 0),
                                    'expires_at': volunteer_data.get('expires_at')
                                })
                                
                                total_accesses += volunteer_data.get('access_count', 0)
                                
                                # Track most recent access
                                if volunteer_data.get('last_access'):
                                    volunteer_last_access = datetime.fromisoformat(volunteer_data['last_access'])
                                    if not last_access or volunteer_last_access > last_access:
                                        last_access = volunteer_last_access
                    except:
                        continue
        
        return jsonify({
            'success': True,
            'volunteers': volunteers,
            'stats': {
                'active_count': len(volunteers),
                'total_accesses': total_accesses,
                'last_access': last_access.isoformat() if last_access else None
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'volunteers': [],
            'stats': {
                'active_count': 0,
                'total_accesses': 0,
                'last_access': None
            }
        })        
        
@app.route('/view_uploaded_file/<event_id>/<form_id>/<filename>')
@login_required
def view_uploaded_file(event_id, form_id, filename):
    """View uploaded file in browser"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    file_path = f'static/uploads/events/{event_id}/{form_id}/{filename}'
    
    if not os.path.exists(file_path):
        flash('File not found!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    try:
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # For images, PDFs, and text files, display inline
        if any(mime_type.startswith(type_) for type_ in ['image/', 'application/pdf', 'text/']):
            return send_file(file_path, mimetype=mime_type)
        
        # For other file types, offer download
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype=mime_type
        )
        
    except Exception as e:
        log_message(f"Error viewing file {filename}: {e}", "ERROR")
        flash(f'Error viewing file: {str(e)[:100]}', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

@app.route('/admin/get_feedback_stats')
@login_required
@admin_required
def admin_get_feedback_stats():
    """Get feedback statistics including resolved count"""
    try:
        feedback_data = load_feedback()
        
        total = len(feedback_data)
        new_count = sum(1 for fb in feedback_data if fb.get('status') == 'new')
        read_count = sum(1 for fb in feedback_data if fb.get('status') == 'read')
        responded_count = sum(1 for fb in feedback_data if fb.get('status') == 'responded')
        resolved_count = sum(1 for fb in feedback_data if fb.get('status') == 'resolved')
        
        # Calculate by type
        type_counts = {}
        for fb in feedback_data:
            fb_type = fb.get('type', 'general')
            type_counts[fb_type] = type_counts.get(fb_type, 0) + 1
        
        # Today's feedback
        today = datetime.now().date()
        today_count = 0
        for fb in feedback_data:
            fb_date = datetime.fromisoformat(fb.get('timestamp', '2000-01-01')).date()
            if fb_date == today:
                today_count += 1
        
        # Average rating
        ratings = [fb.get('rating', 0) for fb in feedback_data if fb.get('rating', 0) > 0]
        average_rating = sum(ratings) / len(ratings) if ratings else 0
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'new': new_count,
                'read': read_count,
                'responded': responded_count,
                'resolved': resolved_count,
                'today': today_count,
                'average_rating': round(average_rating, 1),
                'type_counts': type_counts
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/scanner_link/<event_id>/<form_id>')
@login_required
def scanner_link(event_id, form_id):
    """Generate scanner link for mobile app"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the CSV URL
    base_url = os.environ.get('BASE_URL', request.host_url.rstrip('/'))
    csv_url = f"{base_url}/download_csv/{event_id}/{form_id}"
    
    # Create a deep link for the scanner app
    scanner_deep_link = f"eventflow-scanner://scan?csv={csv_url}"
    
    # Also create a web link that redirects to scanner app
    web_scanner_link = f"{base_url}/launch_scanner?csv={csv_url}"
    
    # QR code for the deep link
    qr_code = generate_qr_code(scanner_deep_link)
    
    return render_template('scanner_link.html',
                         event=event,
                         form_id=form_id,
                         csv_url=csv_url,
                         scanner_deep_link=scanner_deep_link,
                         web_scanner_link=web_scanner_link,
                         qr_code=qr_code)

@app.route('/launch_scanner')
def launch_scanner():
    """Launch scanner app from web"""
    csv_url = request.args.get('csv', '')
    
    # Create HTML page that tries to open app, then falls back to web
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Launch EventFlow Scanner</title>
        <script>
            // Try to open the app first
            window.location.href = 'eventflow-scanner://scan?csv={csv_url}';
            
            // If app doesn't open, redirect after 2 seconds
            setTimeout(function() {{
                window.location.href = '/scanner_web_fallback?csv={csv_url}';
            }}, 2000);
        </script>
    </head>
    <body>
        <div style="padding: 20px; text-align: center;">
            <h2>Launching EventFlow Scanner...</h2>
            <p>If the app doesn't open automatically, <a href="/scanner_web_fallback?csv={csv_url}">click here</a>.</p>
        </div>
    </body>
    </html>
    """

@app.route('/scanner_web_fallback')
def scanner_web_fallback():
    """Web-based scanner fallback"""
    csv_url = request.args.get('csv', '')
    
    return render_template('scanner_web_fallback.html',
                         csv_url=csv_url)


@app.route('/update_form_title/<event_id>/<form_id>', methods=['POST'])
@login_required
def update_form_title(event_id, form_id):
    """Edit form title and schedule"""
    event = load_event(event_id)
    if not event:
        flash('Event not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Check authorization
    if event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    # Find the form
    form_index = None
    form = None
    
    for i, f in enumerate(event.get('forms', [])):
        if f.get('id') == form_id:
            form_index = i
            form = f
            break
    
    if form_index is None or not form:
        flash('Form not found!', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get form data from request
        form_title = request.form.get('form_title', '').strip()
        form_description = request.form.get('form_description', '').strip()  # NEW: Get description
        enable_schedule = 'enable_schedule' in request.form
        
        if not form_title:
            flash('Form title is required!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
        # Update form title
        event['forms'][form_index]['title'] = form_title
        
        # Update form description
        event['forms'][form_index]['description'] = form_description  # NEW: Update description
        
        # Update schedule
        if enable_schedule:
            start_datetime = request.form.get('start_datetime', '').strip()
            end_datetime = request.form.get('end_datetime', '').strip()
            notify_on_end = 'notify_on_end' in request.form
            
            # Get existing schedule or create new
            existing_schedule = event['forms'][form_index].get('schedule', {})
            
            schedule = {
                'enabled': True,
                'start_datetime': start_datetime,
                'end_datetime': end_datetime,
                'notify_on_end': notify_on_end,
                'created_at': existing_schedule.get('created_at', datetime.now().isoformat()),
                'notification_sent': existing_schedule.get('notification_sent', False),
                'notification_sent_at': existing_schedule.get('notification_sent_at'),
                'response_count_at_end': existing_schedule.get('response_count_at_end', 0)
            }
            
            # If notify_on_end was just enabled and end_datetime exists, schedule notification
            if (notify_on_end and end_datetime and 
                (not existing_schedule or not existing_schedule.get('notify_on_end'))):
                
                user_email = session.get('email')
                username = session.get('username', 'User')
                
                schedule_form_notification(
                    event_id=event_id,
                    form_id=form_id,
                    form_title=form_title,
                    end_datetime_str=end_datetime,
                    event_name=event['name'],
                    user_id=session['user_id'],
                    user_email=user_email
                )
        else:
            schedule = None
        
        event['forms'][form_index]['schedule'] = schedule
        
        # Save the event
        save_event(event)
        
        flash('Form updated successfully!', 'success')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
    except Exception as e:
        flash(f'Error updating form: {str(e)[:100]}', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
@app.route('/delete_form/<event_id>/<form_id>', methods=['DELETE'])
@login_required
def delete_form(event_id, form_id):
    """Delete form and all associated data"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        form_index = None
        form_to_delete = None
        
        for i, f in enumerate(event['forms']):
            if f['id'] == form_id:
                form_index = i
                form_to_delete = f
                break
        
        if form_index is None:
            return jsonify({'success': False, 'error': 'Form not found'})
        
        # Remove form from event
        event['forms'].pop(form_index)
        
        # Delete CSV file
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        if os.path.exists(csv_path):
            os.remove(csv_path)
        
        # Delete uploaded files
        upload_dir = f'static/uploads/events/{event_id}/{form_id}'
        if os.path.exists(upload_dir):
            import shutil
            shutil.rmtree(upload_dir)
        
        # Delete notification file if exists
        notification_file = f'data/form_notifications/{form_id}.json'
        if os.path.exists(notification_file):
            os.remove(notification_file)
        
        # Save updated event
        save_event(event)
        
        log_message(f"Form {form_id} deleted by user {session['user_id']}", "INFO")
        return jsonify({'success': True, 'message': 'Form deleted successfully'})
        
    except Exception as e:
        log_message(f"Error deleting form {form_id}: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_all_responses/<event_id>/<form_id>', methods=['DELETE'])
@login_required
def delete_all_responses(event_id, form_id):
    """Delete all responses for a form - FIXED VERSION"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        delete_files = request.headers.get('X-Delete-Files') == 'true'
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return jsonify({'success': False, 'error': 'No response data found'})
        
        # Count responses before deletion and save headers
        headers = []
        response_count = 0
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
            if rows:
                headers = rows[0]
                response_count = len(rows) - 1
        
        # Clear CSV file (keep headers only)
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if headers:
                writer.writerow(headers)
        
        # Delete uploaded files if requested
        files_deleted = 0
        if delete_files:
            upload_dir = f'static/uploads/events/{event_id}/{form_id}'
            if os.path.exists(upload_dir):
                import shutil
                # Count files before deletion
                files_deleted = sum(1 for _ in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, _)))
                shutil.rmtree(upload_dir)
                os.makedirs(upload_dir, exist_ok=True)
        
        log_message(f"All responses deleted for form {form_id} by user {session['user_id']}", "INFO")
        return jsonify({
            'success': True, 
            'deleted_count': response_count,
            'files_deleted': files_deleted if delete_files else None,
            'message': f'Deleted {response_count} responses' + (f' and {files_deleted} files' if delete_files and files_deleted > 0 else '')
        })
        
    except Exception as e:
        log_message(f"Error deleting responses for form {form_id}: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/delete_response/<event_id>/<form_id>/<response_id>', methods=['DELETE'])
@login_required
def delete_response(event_id, form_id, response_id):
    """Delete a single response - IMPROVED VERSION"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return jsonify({'success': False, 'error': 'No response data found'})
        
        # Read all rows and find the response to delete
        rows = []
        deleted_row = None
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        if len(rows) <= 1:
            return jsonify({'success': False, 'error': 'No responses found'})
        
        headers = rows[0]
        new_rows = [headers]
        deleted = False
        
        for row in rows[1:]:
            if len(row) > 1 and row[1] == response_id:  # Response ID is at index 1
                deleted = True
                deleted_row = row
                continue
            new_rows.append(row)
        
        if not deleted:
            return jsonify({'success': False, 'error': 'Response not found'})
        
        # Write back to file
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(new_rows)
        
        # Clean up uploaded files for this response
        files_deleted = 0
        if deleted_row:
            upload_dir = f'static/uploads/events/{event_id}/{form_id}'
            if os.path.exists(upload_dir):
                # Check all columns for file references (columns after Attendee IP)
                for i in range(3, len(deleted_row)):  # Start from column 3 (after Timestamp, Response ID, Attendee IP)
                    cell_value = deleted_row[i]
                    if cell_value and cell_value.strip():
                        # Handle comma-separated filenames
                        filenames = [f.strip() for f in cell_value.split(',')]
                        for filename in filenames:
                            file_path = os.path.join(upload_dir, filename)
                            if os.path.exists(file_path):
                                os.remove(file_path)
                                files_deleted += 1
        
        log_message(f"Response {response_id} deleted from form {form_id} by user {session['user_id']}", "INFO")
        return jsonify({
            'success': True, 
            'message': 'Response deleted successfully',
            'response_id': response_id,
            'files_deleted': files_deleted
        })
        
    except Exception as e:
        log_message(f"Error deleting response {response_id}: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/delete_selected_responses/<event_id>/<form_id>', methods=['DELETE'])
@login_required
def delete_selected_responses(event_id, form_id):
    """Delete multiple selected responses - IMPROVED VERSION"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        response_ids = data.get('response_ids', [])
        
        if not response_ids:
            return jsonify({'success': False, 'error': 'No response IDs provided'})
        
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return jsonify({'success': False, 'error': 'No response data found'})
        
        # Read all rows
        rows = []
        deleted_rows = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
        
        if len(rows) <= 1:
            return jsonify({'success': False, 'error': 'No responses found'})
        
        # Filter out selected responses
        headers = rows[0]
        new_rows = [headers]
        deleted_count = 0
        
        for row in rows[1:]:
            if len(row) > 1 and row[1] in response_ids:
                deleted_count += 1
                deleted_rows.append(row)
                continue
            new_rows.append(row)
        
        if deleted_count == 0:
            return jsonify({'success': False, 'error': 'No matching responses found'})
        
        # Write back to file
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(new_rows)
        
        # Clean up uploaded files for deleted responses
        files_deleted = 0
        upload_dir = f'static/uploads/events/{event_id}/{form_id}'
        if os.path.exists(upload_dir) and deleted_rows:
            for deleted_row in deleted_rows:
                # Check all columns for file references
                for i in range(3, len(deleted_row)):
                    cell_value = deleted_row[i]
                    if cell_value and cell_value.strip():
                        filenames = [f.strip() for f in cell_value.split(',')]
                        for filename in filenames:
                            file_path = os.path.join(upload_dir, filename)
                            if os.path.exists(file_path):
                                os.remove(file_path)
                                files_deleted += 1
        
        log_message(f"{deleted_count} responses deleted from form {form_id} by user {session['user_id']}", "INFO")
        return jsonify({
            'success': True, 
            'deleted_count': deleted_count,
            'files_deleted': files_deleted,
            'message': f'Successfully deleted {deleted_count} response(s)'
        })
        
    except Exception as e:
        log_message(f"Error deleting selected responses: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_response_ids/<event_id>/<form_id>')
@login_required
def get_response_ids(event_id, form_id):
    """Get all response IDs for a form (for bulk operations)"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return jsonify({'success': False, 'error': 'No response data found'})
        
        response_ids = []
        response_data = []
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                response_id = row.get('Response ID')
                if response_id:
                    response_ids.append(response_id)
                    response_data.append({
                        'id': response_id,
                        'timestamp': row.get('Timestamp'),
                        'attendee_ip': row.get('Attendee IP'),
                        'summary': ', '.join([f"{k}: {v}" for k, v in list(row.items())[:5] if k not in ['Timestamp', 'Response ID', 'Attendee IP']])
                    })
        
        return jsonify({
            'success': True,
            'response_ids': response_ids,
            'responses': response_data,
            'total_count': len(response_ids)
        })
        
    except Exception as e:
        log_message(f"Error getting response IDs: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})        

@app.route('/test_guidelines', methods=['GET', 'POST'])
def test_guidelines():
    """Simple test route to check AJAX"""
    return jsonify({
        'success': True,
        'message': 'Test route works!',
        'user_id': session.get('user_id'),
        'time': datetime.now().isoformat()
    })
    
@app.route('/guidelines')
def user_guidelines():
    """Display user guidelines"""
    users = load_users()
    user_id = session.get('user_id')
    user_data = users.get(user_id, {})
    
    return render_template('user_guidelines.html',
                         user_id=user_id,
                         guidelines_accepted=user_data.get('guidelines_accepted', False),
                         username=session.get('username'))

@app.route('/fix_all_users_verification')
def fix_all_users_verification():
    """Fix email verification for all users"""
    users = load_users()
    fixed_count = 0
    
    for user_id, user_data in users.items():
        # If user has email but no email_verified field, set it to True
        if user_data.get('email') and 'email_verified' not in user_data:
            user_data['email_verified'] = True
            fixed_count += 1
        # If email_verified is False but user has email, set to True
        elif user_data.get('email') and user_data.get('email_verified') == False:
            user_data['email_verified'] = True
            fixed_count += 1
    
    save_users(users)
    return f"Fixed {fixed_count} users. All users with email now have email_verified=True"

@app.route('/delete_event/<event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    """Delete an event and all associated data"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        # Count forms and responses before deletion
        form_count = len(event.get('forms', []))
        total_responses = 0
        
        # Count responses in each form
        for form in event.get('forms', []):
            csv_path = f'data/events/{event_id}/{form["id"]}.csv'
            if os.path.exists(csv_path):
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    total_responses += max(0, len(list(reader)) - 1)
        
        # Delete form CSV files
        for form in event.get('forms', []):
            csv_path = f'data/events/{event_id}/{form["id"]}.csv'
            if os.path.exists(csv_path):
                os.remove(csv_path)
            
            # Delete uploaded files
            upload_dir = f'static/uploads/events/{event_id}/{form["id"]}'
            if os.path.exists(upload_dir):
                import shutil
                shutil.rmtree(upload_dir)
            
            # Delete notification files
            notification_file = f'data/form_notifications/{form["id"]}.json'
            if os.path.exists(notification_file):
                os.remove(notification_file)
        
        # Delete event directory
        event_dir = f'data/events/{event_id}'
        if os.path.exists(event_dir):
            import shutil
            shutil.rmtree(event_dir)
        
        # Delete event file
        event_file = f'data/events/{event_id}.json'
        if os.path.exists(event_file):
            os.remove(event_file)
        
        # Delete event uploads directory
        event_uploads_dir = f'static/uploads/events/{event_id}'
        if os.path.exists(event_uploads_dir):
            import shutil
            shutil.rmtree(event_uploads_dir)
        
        log_message(f"Event {event_id} deleted by user {session['user_id']}. "
                   f"Deleted {form_count} forms and {total_responses} responses.", "INFO")
        
        return jsonify({
            'success': True,
            'message': 'Event deleted successfully',
            'form_count': form_count,
            'response_count': total_responses
        })
        
    except Exception as e:
        log_message(f"Error deleting event {event_id}: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# TEMPLATE FILTERS AND FUNCTIONS
# ============================================================================

# Add this to your template filters section in app.py
@app.template_filter()
def truncate_string(s, length=30, end='...'):
    """Truncate string with customizable end"""
    if not s:
        return ""
    
    if len(s) <= length:
        return s
    
    return s[:length] + end

@app.template_filter()
def truncate_middle(s, length=30, end='...'):
    """Truncate string from middle"""
    if not s:
        return ""
    
    if len(s) <= length:
        return s
    
    half = length // 2
    return s[:half] + end + s[-half:]

# Then in your template, use:
# {{ form.id|truncate_string(8) }}

@app.template_filter('check_form_active')
def check_form_active_filter(form_data):
    """Check if form is active (for use in templates)"""
    if not form_data:
        return True, "Form is active"
    
    try:
        schedule = form_data.get('schedule')
        if not schedule:
            return True, "Form is active"
        
        start_datetime = schedule.get('start_datetime')
        end_datetime = schedule.get('end_datetime')
        
        now = datetime.now()
        
        # Check if before start time
        if start_datetime:
            try:
                # Handle different formats
                start_time = None
                if 'T' in start_datetime:
                    start_time = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
                else:
                    # Try multiple formats
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                        try:
                            start_time = datetime.strptime(start_datetime, fmt)
                            break
                        except ValueError:
                            continue
                
                if start_time and now < start_time:
                    time_diff = start_time - now
                    hours = int(time_diff.total_seconds() // 3600)
                    minutes = int((time_diff.total_seconds() % 3600) // 60)
                    return False, f"Form opens in {hours}h {minutes}m"
            except:
                pass  # If parsing fails, continue
        
        # Check if after end time
        if end_datetime:
            try:
                # Handle different formats
                end_time = None
                if 'T' in end_datetime:
                    end_time = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
                else:
                    # Try multiple formats
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                        try:
                            end_time = datetime.strptime(end_datetime, fmt)
                            break
                        except ValueError:
                            continue
                
                if end_time and now > end_time:
                    return False, "Form has closed"
            except:
                pass  # If parsing fails, continue
        
        # Form is active
        return True, "Form is active"
        
    except Exception as e:
        log_message(f"Error checking form schedule in template: {e}", "ERROR")
        return True, "Form is active"  # Default to active if error

@app.template_filter()
def check_form_active(form_data):
    """Check if form is active (for use in templates)"""
    if not form_data:
        return True, "Form is active"
    
    try:
        schedule = form_data.get('schedule')
        if not schedule:
            return True, "Form is active"
        
        start_datetime = schedule.get('start_datetime')
        end_datetime = schedule.get('end_datetime')
        
        now = datetime.now()
        
        # Check if before start time
        if start_datetime:
            try:
                # Handle different formats
                start_time = None
                if 'T' in start_datetime:
                    start_time = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
                else:
                    # Try multiple formats
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                        try:
                            start_time = datetime.strptime(start_datetime, fmt)
                            break
                        except ValueError:
                            continue
                
                if start_time and now < start_time:
                    time_diff = start_time - now
                    hours = int(time_diff.total_seconds() // 3600)
                    minutes = int((time_diff.total_seconds() % 3600) // 60)
                    return False, f"Form opens in {hours}h {minutes}m"
            except:
                pass  # If parsing fails, continue
        
        # Check if after end time
        if end_datetime:
            try:
                # Handle different formats
                end_time = None
                if 'T' in end_datetime:
                    end_time = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
                else:
                    # Try multiple formats
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                        try:
                            end_time = datetime.strptime(end_datetime, fmt)
                            break
                        except ValueError:
                            continue
                
                if end_time and now > end_time:
                    return False, "Form has closed"
            except:
                pass  # If parsing fails, continue
        
        # Form is active
        return True, "Form is active"
        
    except Exception as e:
        log_message(f"Error checking form schedule in template: {e}", "ERROR")
        return True, "Form is active"  # Default to active if error



# ============================================================================
# DEBUG EMAIL ROUTES
# ============================================================================

@app.route('/debug_share_form_email/<event_id>/<form_id>/<email>')
@login_required
def debug_share_form_email(event_id, form_id, email):
    """Debug: Send the exact email that would be sent from share form"""
    try:
        event = load_event(event_id)
        if not event or event.get('creator_id') != session['user_id']:
            flash('Unauthorized!', 'error')
            return redirect(url_for('dashboard'))
        
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            flash('Form not found!', 'error')
            return redirect(url_for('dashboard'))
        
        form_url = url_for('show_form', form_id=form_id, _external=True)
        
        log_message(f"🔧 DEBUG_SHARE_FORM: Testing exact share form email", "DEBUG")
        log_message(f"🔧 DEBUG_SHARE_FORM: To: {email}", "DEBUG")
        log_message(f"🔧 DEBUG_SHARE_FORM: Form URL: {form_url}", "DEBUG")
        
        # Create the EXACT email that would be sent
        subject = f"📋 Registration: {form['title']}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .btn {{ background: #4361ee; color: white; padding: 12px 24px; text-decoration: none; 
                        border-radius: 6px; display: inline-block; margin: 20px 0; }}
                .custom-message {{ background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .debug-info {{ background: #f1f5f9; padding: 10px; border-radius: 5px; margin: 15px 0; font-family: monospace; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📋 Event Registration Invitation</h1>
                </div>
                <div style="padding: 30px;">
                    <p>Hello,</p>
                    
                    <p>You're invited to register for:</p>
                    <h2>{event['name']}</h2>
                    <p><strong>Form:</strong> {form['title']}</p>
                    
                    <div class="debug-info">
                        <strong>🔧 DEBUG EMAIL - FROM SHARE FORM:</strong><br>
                        • Form ID: {form_id}<br>
                        • Event ID: {event_id}<br>
                        • Form URL: {form_url}<br>
                        • Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                        • This is the EXACT email sent from Share Form
                    </div>
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="{form_url}" class="btn">📝 Register Now</a>
                    </div>
                    
                    <p>Or copy this link:</p>
                    <div style="background: #f1f5f9; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <code>{form_url}</code>
                    </div>
                    
                    <p>Sent by: <strong>{session.get('username', 'User')}</strong></p>
                    
                    <div class="footer">
                        <p>EventFlow Registration System</p>
                        <p>© {datetime.now().year}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send using the SAME function
        success, message = send_email_simple(email, subject, html_content)
        
        if success:
            flash(f'✅ Debug email sent successfully to {email}!', 'success')
            flash(f'🔧 This is the EXACT email that would be sent from the Share Form.', 'info')
            flash(f'📝 If this works but Share Form doesn\'t, check form URL generation.', 'info')
        else:
            flash(f'❌ Debug email failed: {message}', 'error')
            flash(f'🔧 This shows why Share Form emails are failing.', 'error')
            
    except Exception as e:
        error_msg = str(e)
        log_message(f"❌ DEBUG_SHARE_FORM error: {error_msg}", "ERROR")
        flash(f'❌ Debug error: {error_msg[:200]}', 'error')
    
    return redirect(url_for('share_form', event_id=event_id, form_id=form_id))

# Also add the debug_email route if it's referenced
@app.route('/debug_email/<email>')
@login_required
def debug_email(email):
    """Debug email sending to a specific email"""
    try:
        log_message(f"🔍 DEBUGGING email to: {email}", "DEBUG")
        
        # Test with simple text email first
        subject = "🔍 EventFlow Debug Test"
        html_content = f"""
        <h2>Debug Test Email</h2>
        <p>This is a debug email sent to: {email}</p>
        <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>From: {MAIL_USERNAME}</p>
        """
        
        # Create simple message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = MAIL_USERNAME
        msg['To'] = email
        
        # Add both plain text and HTML
        msg.attach(MIMEText('This is a debug test email', 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        # Try to send with detailed debug
        log_message(f"🔍 Connecting to {MAIL_SERVER}:{MAIL_PORT}", "DEBUG")
        
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=30)
        server.set_debuglevel(2)  # Maximum debug output
        
        try:
            server.ehlo()
            server.starttls()
            server.ehlo()
            
            log_message(f"🔍 Logging in as: {MAIL_USERNAME}", "DEBUG")
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            
            log_message(f"🔍 Sending to: {email}", "DEBUG")
            server.sendmail(MAIL_USERNAME, email, msg.as_string())
            
            server.quit()
            log_message(f"✅ DEBUG: Email sent successfully to {email}", "SUCCESS")
            flash(f'✅ Debug email sent to {email}! Check console for details.', 'success')
            
        except Exception as e:
            log_message(f"❌ DEBUG SMTP Error: {repr(e)}", "ERROR")
            flash(f'❌ Debug email failed: {str(e)[:100]}', 'error')
            if hasattr(e, 'smtp_code'):
                flash(f'SMTP Code: {e.smtp_code}', 'error')
            if hasattr(e, 'smtp_error'):
                flash(f'SMTP Error: {e.smtp_error}', 'error')
            
    except Exception as e:
        log_message(f"❌ DEBUG General Error: {repr(e)}", "ERROR")
        flash(f'❌ General error: {str(e)[:100]}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/test_email')
@login_required
def test_email():
    """Test email route using EXACT same configuration as real emails"""
    try:
        if not MAIL_USERNAME or not MAIL_PASSWORD:
            flash('❌ Email not configured in .env file', 'error')
            return redirect(url_for('dashboard'))
        
        log_message("🧪 STARTING IDENTICAL TEST EMAIL - USING REAL EMAIL CONFIG", "INFO")
        
        # Create test data that matches real email structure
        form_url = url_for('index', _external=True)
        form_title = "Test Registration Form"
        event_name = "Test Event - EventFlow"
        sender_name = session.get('username', 'Test User')
        custom_message = "This is a test email to verify that the email system is working correctly with the same configuration used for real form invitations."
        
        # Create the EXACT same HTML content as real emails
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .btn {{ background: #4361ee; color: white; padding: 12px 24px; text-decoration: none; 
                        border-radius: 6px; display: inline-block; margin: 20px 0; }}
                .custom-message {{ background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .debug-info {{ background: #f1f5f9; padding: 10px; border-radius: 5px; margin: 15px 0; font-family: monospace; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📋 Event Registration Invitation</h1>
                </div>
                <div style="padding: 30px;">
                    <p>Hello,</p>
                    
                    <p>You're invited to register for:</p>
                    <h2>{event_name}</h2>
                    <p><strong>Form:</strong> {form_title}</p>
                    
                    <div class="custom-message">
                        <p><strong>Message from {sender_name}:</strong><br>{custom_message}</p>
                    </div>
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <a href="{form_url}" class="btn">📝 Register Now</a>
                    </div>
                    
                    <p>Or copy this link:</p>
                    <div style="background: #f1f5f9; padding: 15px; border-radius: 6px; margin: 15px 0;">
                        <code>{form_url}</code>
                    </div>
                    
                    <div class="debug-info">
                        <strong>🧪 TEST EMAIL DEBUG INFO:</strong><br>
                        • Sender: {MAIL_USERNAME}<br>
                        • Server: {MAIL_SERVER}:{MAIL_PORT}<br>
                        • Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                        • User Agent: EventFlow Test System
                    </div>
                    
                    <p>Sent by: <strong>{sender_name}</strong></p>
                    
                    <div class="footer">
                        <p>EventFlow Registration System</p>
                        <p>© {datetime.now().year}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Use the SAME email function as real emails
        success, message = send_email_simple(
            MAIL_USERNAME,
            f"📋 Registration: {form_title}",
            html_content
        )
        
        if success:
            flash(f'✅ Test email sent successfully to {MAIL_USERNAME}! Check your inbox (and spam folder).', 'success')
            flash('🔧 This test uses the EXACT same configuration as real form invitations.', 'info')
        else:
            flash(f'❌ Test email failed: {message}', 'error')
            flash('🔧 This failure means real form invitations will also fail with the same error.', 'warning')
            
    except Exception as e:
        error_msg = str(e)
        flash(f'❌ Test error: {error_msg[:100]}', 'error')
    
    return redirect(url_for('dashboard'))

# ============================================================================
# FORM END NOTIFICATION ROUTES
# ============================================================================

@app.route('/check_forms_end')
@login_required
def check_forms_end():
    """Manually trigger form end checking (for testing and admin)"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    ended_forms = check_ended_forms()
    
    if ended_forms:
        flash(f'Checked forms: {len(ended_forms)} forms have ended recently', 'success')
    else:
        flash('No forms have ended recently', 'info')
    
    return redirect(url_for('dashboard'))

@app.route('/send_test_notification/<event_id>/<form_id>', methods=['POST'])
@login_required
def send_test_notification(event_id, form_id):
    """Send test notification email for form end"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    form = None
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form = f
            break
    
    if not form:
        return jsonify({'success': False, 'error': 'Form not found'})
    
    # Get response count
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    response_count = 0
    if os.path.exists(csv_path):
        with open(csv_path, 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            response_count = max(0, len(list(reader)) - 1)
    
    # Send test notification
    success = send_form_end_notification(
        event_id,
        form_id,
        form['title'],
        event['name'],
        session['email'],
        session['username'],
        response_count
    )
    
    if success:
        log_message(f"✅ Test form end notification sent to {session['email']} for form '{form['title']}'", "SUCCESS")
        return jsonify({'success': True, 'message': 'Test notification sent!'})
    else:
        log_message(f"❌ Failed to send test notification for form '{form['title']}'", "ERROR")
        return jsonify({'success': False, 'error': 'Failed to send notification'})

@app.route('/manual_check_form_end/<event_id>/<form_id>')
@login_required
def manual_check_form_end(event_id, form_id):
    """Manually trigger form end check for testing"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    form = None
    for f in event.get('forms', []):
        if f['id'] == form_id:
            form = f
            break
    
    if not form:
        flash('Form not found!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    schedule = form.get('schedule')
    if not schedule:
        flash('Form has no schedule!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    # Check if form has ended
    if schedule.get('end_datetime'):
        try:
            end_datetime = datetime.fromisoformat(
                schedule.get('end_datetime').replace('T', ' ') if 'T' in schedule.get('end_datetime') else schedule.get('end_datetime')
            )
            now = datetime.now()
            
            if now >= end_datetime:
                # Check if notification should be sent
                if schedule.get('notify_on_end') and not schedule.get('notification_sent'):
                    # Send notification
                    csv_path = f'data/events/{event_id}/{form_id}.csv'
                    response_count = 0
                    if os.path.exists(csv_path):
                        with open(csv_path, 'r', encoding='utf-8') as csv_file:
                            reader = csv.reader(csv_file)
                            response_count = max(0, len(list(reader)) - 1)
                    
                    # Send notification
                    sent = send_form_end_notification(
                        event_id,
                        form_id,
                        form['title'],
                        event['name'],
                        session['email'],
                        session['username'],
                        response_count
                    )
                    
                    if sent:
                        # Mark as sent in the event data
                        for f in event['forms']:
                            if f['id'] == form_id:
                                sched = f.get('schedule', {})
                                sched['notification_sent'] = True
                                sched['notification_sent_at'] = now.isoformat()
                                sched['response_count_at_end'] = response_count
                                break
                        
                        # Save the change to disk
                        save_event(event)
                        
                        flash('Notification sent successfully!', 'success')
                    else:
                        flash('Failed to send notification', 'error')
                else:
                    if not schedule.get('notify_on_end'):
                        flash('Notification not enabled for this form', 'info')
                    else:
                        flash('Notification already sent', 'info')
            else:
                flash('Form has not ended yet', 'info')
        except Exception as e:
            flash(f'Error checking form: {str(e)[:100]}', 'error')
    else:
        flash('Form has no end datetime', 'info')
    
    return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

# ============================================================================
# FEEDBACK ROUTES
# ============================================================================

@app.route('/feedback')
def feedback():
    """Show feedback form"""
    return render_template('feedback_form.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    """Handle feedback submission"""
    try:
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        rating = int(request.form.get('rating', 0))
        feedback_type = request.form.get('type', 'general')
        message = request.form.get('message', '').strip()
        source = request.form.get('source', '').strip()
        context = request.form.get('context', '').strip()
        can_contact = request.form.get('can_contact') == 'on'
        user_id = request.form.get('user_id')
        
        # Validate required fields
        if not name or not email or not message:
            return jsonify({
                'success': False, 
                'error': 'Name, email, and message are required'
            })
        
        # Validate email format
        if '@' not in email or '.' not in email:
            return jsonify({
                'success': False, 
                'error': 'Please enter a valid email address'
            })
        
        # Validate rating
        if rating < 0 or rating > 5:
            return jsonify({
                'success': False, 
                'error': 'Invalid rating value'
            })
        
        # Create feedback entry
        feedback_entry = {
            'id': str(uuid.uuid4()),
            'name': name,
            'email': email,
            'rating': rating,
            'type': feedback_type,
            'message': message,
            'source': source,
            'context': context,
            'can_contact': can_contact,
            'user_id': user_id or None,
            'timestamp': datetime.now().isoformat(),
            'status': 'new',
            'reviewed': False,
            'reviewed_at': None,
            'reviewed_by': None
        }
        
        # Load existing feedback
        feedback_data = load_feedback()
        feedback_data.append(feedback_entry)
        
        # Save feedback
        if save_feedback(feedback_data):
            log_message(f"Feedback submitted by {name} ({email}) - Type: {feedback_type}, Rating: {rating}", "INFO")
            
            # Send notification email to admin
            send_feedback_notification(feedback_entry)
            
            # Send thank you email to user
            email_sent = send_thank_you_email(
                email, 
                name, 
                feedback_entry['id'],
                feedback_type,
                rating,
                message
            )
            
            response_data = {
                'success': True,
                'message': 'Thank you for your feedback! We\'ve received your submission.',
                'feedback_id': feedback_entry['id'],
                'email_sent': email_sent
            }
            
            if email_sent:
                response_data['message'] += ' A confirmation email has been sent to your inbox.'
            else:
                response_data['message'] += ' (Note: Confirmation email could not be sent)'
            
            return jsonify(response_data)
        else:
            return jsonify({
                'success': False, 
                'error': 'Failed to save feedback'
            })
            
    except Exception as e:
        log_message(f"Error submitting feedback: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/feedback/viewer')
@login_required
def feedback_viewer():
    """Feedback viewer page for users to see their own feedback"""
    try:
        feedback_data = load_feedback()
        
        # Filter to show only current user's feedback
        user_feedback = []
        for fb in feedback_data:
            # Match by user_id or email
            if fb.get('user_id') == session['user_id'] or fb.get('email') == session.get('email'):
                user_feedback.append(fb)
        
        # Sort by newest first
        user_feedback.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Calculate statistics
        ratings = [fb.get('rating', 0) for fb in user_feedback if fb.get('rating', 0) > 0]
        average_rating = sum(ratings) / len(ratings) if ratings else 0
        
        stats = {
            'total_feedback': len(user_feedback),
            'average_rating': round(average_rating, 1),
            'with_rating': len(ratings),
        }
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10
        total_items = len(user_feedback)
        total_pages = (total_items + per_page - 1) // per_page
        
        # Validate page number
        if page < 1:
            page = 1
        elif page > total_pages and total_pages > 0:
            page = total_pages
        
        # Get items for current page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_feedback = user_feedback[start_idx:end_idx]
        
        return render_template('feedback_viewer.html',
                             feedback_list=paginated_feedback,
                             stats=stats,
                             page=page,
                             total_pages=total_pages)
                             
    except Exception as e:
        flash('Error loading feedback. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/feedback_receiver')
@login_required
def admin_feedback_receiver():
    """Admin feedback dashboard page"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    # Load feedback with filtering
    feedback_data = load_feedback()
    
    # Apply filters from query parameters
    status_filter = request.args.get('status', 'all')
    type_filter = request.args.get('type', 'all')
    rating_filter = request.args.get('rating', 'all')
    date_filter = request.args.get('date', 'all')
    search_query = request.args.get('search', '')
    
    filtered_feedback = []
    for fb in feedback_data:
        # Status filter
        if status_filter != 'all' and fb.get('status') != status_filter:
            continue
        
        # Type filter
        if type_filter != 'all' and fb.get('type') != type_filter:
            continue
        
        # Rating filter
        if rating_filter != 'all' and str(fb.get('rating', 0)) != rating_filter:
            continue
        
        # Date filter
        if date_filter != 'all':
            fb_date = datetime.fromisoformat(fb.get('timestamp', '2000-01-01'))
            today = datetime.now()
            
            if date_filter == 'today':
                if fb_date.date() != today.date():
                    continue
            elif date_filter == 'week':
                week_ago = today - timedelta(days=7)
                if fb_date < week_ago:
                    continue
            elif date_filter == 'month':
                month_ago = today - timedelta(days=30)
                if fb_date < month_ago:
                    continue
            elif date_filter == 'year':
                year_ago = today - timedelta(days=365)
                if fb_date < year_ago:
                    continue
        
        # Search filter
        if search_query:
            search_lower = search_query.lower()
            searchable_fields = [
                fb.get('name', ''),
                fb.get('email', ''),
                fb.get('message', ''),
                fb.get('source', ''),
                fb.get('context', '')
            ]
            if not any(search_lower in str(field).lower() for field in searchable_fields):
                continue
        
        filtered_feedback.append(fb)
    
    # Sort by newest first
    filtered_feedback.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = 20
    total = len(filtered_feedback)
    total_pages = (total + per_page - 1) // per_page
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_feedback = filtered_feedback[start_idx:end_idx]
    
    # Calculate statistics
    stats = calculate_feedback_stats(feedback_data)
    
    return render_template('admin_feedback_receiver.html',
                         feedback_list=paginated_feedback,
                         stats=stats,
                         avg_rating=stats.get('average_rating', 0),  # ADDED THIS LINE
                         page=page,
                         total_pages=total_pages)

@app.route('/admin/send_feedback_reply', methods=['POST'])
@login_required
@admin_required
def admin_send_feedback_reply():
    """Send reply to feedback"""
    try:
        data = request.json
        feedback_id = data.get('feedback_id')
        subject = data.get('subject')
        message = data.get('message')
        status = data.get('status', 'responded')
        
        if not all([feedback_id, subject, message]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Load feedback
        feedback_data = load_feedback()
        
        # Find the feedback
        feedback = None
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                feedback = fb
                break
        
        if not feedback:
            return jsonify({'success': False, 'error': 'Feedback not found'})
        
        # Update feedback status
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                fb['status'] = status
                fb['responded_at'] = datetime.now().isoformat()
                fb['responded_by'] = session['user_id']
                fb['response_message'] = message
                break
        
        # Save feedback
        save_feedback(feedback_data)
        
        # Send email to user
        email_sent = False
        if feedback.get('email'):
            # Simple email sending - you can enhance this
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <h2>Response to Your Feedback</h2>
                <p>Dear {feedback.get('name')},</p>
                <p>Thank you for your feedback. Here is our response:</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    {message}
                </div>
                <p>Best regards,<br>EventFlow Support Team</p>
            </body>
            </html>
            """
            
            success, _ = send_email_simple(
                feedback['email'],
                subject,
                html_content
            )
            email_sent = success
        
        log_message(f"Reply sent to feedback {feedback_id} by admin {session['user_id']}", "ADMIN")
        return jsonify({
            'success': True,
            'message': 'Reply sent successfully',
            'email_sent': email_sent
        })
        
    except Exception as e:
        log_message(f"Error sending feedback reply: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/send_feedback_followup', methods=['POST'])
@login_required
@admin_required
def admin_send_feedback_followup():
    """Send follow-up email for feedback"""
    try:
        data = request.json
        feedback_id = data.get('feedback_id')
        subject = data.get('subject')
        message = data.get('message')
        
        if not all([feedback_id, subject, message]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Load feedback
        feedback_data = load_feedback()
        
        # Find the feedback
        feedback = None
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                feedback = fb
                break
        
        if not feedback:
            return jsonify({'success': False, 'error': 'Feedback not found'})
        
        # Send email
        email_sent = False
        if feedback.get('email'):
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <h2>Follow-up on Your Feedback</h2>
                <p>Dear {feedback.get('name')},</p>
                <p>We're following up on your recent feedback:</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    {message}
                </div>
                <p>If you have any additional information, please reply to this email.</p>
                <p>Best regards,<br>EventFlow Support Team</p>
            </body>
            </html>
            """
            
            success, _ = send_email_simple(
                feedback['email'],
                subject,
                html_content
            )
            email_sent = success
        
        log_message(f"Follow-up sent for feedback {feedback_id} by admin {session['user_id']}", "ADMIN")
        return jsonify({
            'success': True,
            'message': 'Follow-up sent successfully',
            'email_sent': email_sent
        })
        
    except Exception as e:
        log_message(f"Error sending feedback follow-up: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_feedback/<feedback_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_feedback(feedback_id):
    """Delete a feedback item"""
    try:
        feedback_data = load_feedback()
        
        # Find and remove the feedback
        new_feedback_data = [fb for fb in feedback_data if fb['id'] != feedback_id]
        
        if len(new_feedback_data) == len(feedback_data):
            return jsonify({'success': False, 'error': 'Feedback not found'})
        
        # Save updated feedback
        save_feedback(new_feedback_data)
        
        log_message(f"Feedback {feedback_id} deleted by admin {session['user_id']}", "ADMIN")
        return jsonify({'success': True, 'message': 'Feedback deleted successfully'})
        
    except Exception as e:
        log_message(f"Error deleting feedback: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})        

@app.route('/contact_creator', methods=['POST'])
def contact_creator():
    """Send message to form creator"""
    try:
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        creator_email = request.form.get('creator_email', '').strip()
        form_title = request.form.get('form_title', '')
        event_name = request.form.get('event_name', '')
        form_id = request.form.get('form_id', '')
        event_id = request.form.get('event_id', '')
        
        # Validation
        if not all([name, email, subject, message, creator_email]):
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        if '@' not in email or '.' not in email:
            return jsonify({'success': False, 'error': 'Please enter a valid email address'})
        
        if '@' not in creator_email or '.' not in creator_email:
            return jsonify({'success': False, 'error': 'Creator email is invalid'})
        
        # Create email content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
                .header {{ background: #4361ee; color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center; }}
                .message-box {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4361ee; }}
                .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
                .info-box {{ background: #e8f4fd; padding: 15px; border-radius: 6px; margin: 15px 0; }}
                .btn {{ background: #4361ee; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>📧 Message About Your Form</h2>
                    <p>A user has sent you a message about your form</p>
                </div>
                
                <div class="info-box">
                    <p><strong>Form:</strong> {form_title}</p>
                    <p><strong>Event:</strong> {event_name}</p>
                    <p><strong>From:</strong> {name} ({email})</p>
                    <p><strong>Subject:</strong> {subject}</p>
                </div>
                
                <div class="message-box">
                    <p><strong>Message:</strong></p>
                    <p style="white-space: pre-wrap;">{message}</p>
                </div>
                
                <div style="text-align: center; margin: 25px 0;">
                    <a href="mailto:{email}" class="btn">
                        <i class="bi bi-reply"></i> Reply to {name}
                    </a>
                </div>
                
                <div style="background: #f1f5f9; padding: 15px; border-radius: 6px; margin: 20px 0;">
                    <p><strong>Quick Links:</strong></p>
                    <p>• <a href="{url_for('view_form', event_id=event_id, form_id=form_id, _external=True)}">View Form: {form_title}</a></p>
                    <p>• <a href="{url_for('dashboard', _external=True)}">Your EventFlow Dashboard</a></p>
                </div>
                
                <div class="footer">
                    <p>This message was sent through EventFlow's contact system.</p>
                    <p>You can disable contact messages in your account settings.</p>
                    <p>© {datetime.now().year} EventFlow</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send email to creator
        success, error_msg = send_email_simple(creator_email, subject, html_content)
        
        if success:
            # Also send confirmation to the sender
            confirmation_html = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body>
                <div style="padding: 20px; font-family: Arial, sans-serif;">
                    <h2>✅ Message Sent Successfully</h2>
                    <p>Hi {name},</p>
                    <p>Your message to the creator of "{form_title}" has been sent successfully.</p>
                    <p><strong>To:</strong> {creator_email}</p>
                    <p><strong>Subject:</strong> {subject}</p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                        {message[:200]}{'...' if len(message) > 200 else ''}
                    </div>
                    <p>The form creator should receive your message shortly and can reply to you directly at {email}.</p>
                    <p>Thank you for using EventFlow!</p>
                </div>
            </body>
            </html>
            """
            
            # Send confirmation to sender (optional)
            send_email_simple(email, f"Message sent: {subject}", confirmation_html)
            
            log_message(f"Contact message sent from {email} to creator {creator_email} for form {form_id}", "INFO")
            return jsonify({'success': True, 'message': 'Message sent successfully'})
        else:
            log_message(f"Failed to send contact message: {error_msg}", "ERROR")
            return jsonify({'success': False, 'error': error_msg})
            
    except Exception as e:
        log_message(f"Error in contact_creator: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# HOW IT WORKS ROUTES
# ============================================================================

@app.route('/how-it-works')
def how_it_works():
    """Main How It Works page with step overview"""
    return render_template('how_it_works.html')

@app.route('/how-it-works/step/<int:step>')
def how_it_works_step(step):
    """Individual step page for how it works guide"""
    if step < 1 or step > 4:
        flash('Invalid step number', 'error')
        return redirect(url_for('how_it_works'))
    
    # Get step data
    step_data = get_step_data(step)
    
    # Try to find video file using our discovery function
    video_path = find_video_file(step)
    
    # Handle video data
    if video_path and os.path.exists(video_path):
        # Get the filename from the path
        filename = os.path.basename(video_path)
        
        # Set the video file path for the template
        video_static_path = f"videos/how-it-works/{filename}"
        step_data['video_file'] = video_static_path
        step_data['video_type'] = 'file'
        step_data['video'] = True
        
        # Generate direct URLs
        step_data['video_url_direct'] = f"/static/videos/how-it-works/{filename}"
        step_data['video_url_step'] = f"/video/{step}"
        
        # Generate thumbnail URL if needed
        thumbnail_path = video_path.replace('.mp4', '.jpg').replace('.webm', '.jpg').replace('.mov', '.jpg')
        if os.path.exists(thumbnail_path):
            step_data['video_thumbnail'] = f"/static/videos/how-it-works/{os.path.basename(thumbnail_path)}"
        else:
            step_data['video_thumbnail'] = None
    else:
        # No video available
        step_data['video'] = False
        step_data['video_file'] = None
        step_data['video_type'] = None
        step_data['video_thumbnail'] = None
        step_data['video_url_direct'] = None
        step_data['video_url_step'] = None
    
    # Get all step data for navigation
    step_data_all = get_all_step_data()
    
    # Get navigation info
    navigation = get_step_navigation(step)
    
    # Map action URLs
    action_url_map = {
        1: url_for('signup'),
        2: url_for('create_event'),
        3: url_for('dashboard'),
        4: url_for('signup')
    }
    
    if step in action_url_map:
        step_data['action_url'] = action_url_map[step]
    
    return render_template('how_it_works_step.html', 
                         step=step, 
                         step_data=step_data,
                         step_data_all=step_data_all,
                         navigation=navigation)

@app.route('/video/<int:step>')
def serve_step_video(step):
    """Direct video serving route for step videos"""
    video_path = find_video_file(step)
    
    if not video_path:
        return "Video not found", 404
    
    if not os.path.exists(video_path):
        return "Video file not found on server", 404
    
    # Get the filename
    filename = os.path.basename(video_path)
    
    try:
        return send_from_directory('static/videos/how-it-works', filename)
    except Exception as e:
        app.logger.error(f"Error serving video: {e}")
        return "Error serving video", 500

# ============================================================================
# ADMIN VIDEO MANAGEMENT ROUTES
# ============================================================================

@app.route('/admin/how-it-works/videos')
@login_required
def admin_how_it_works_videos():
    """Admin panel for managing tutorial videos"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    all_videos = video_manager.list_all_videos()
    all_step_data = get_all_step_data()
    
    # Add filename to video info
    for step, video_info in all_videos.items():
        if video_info['path']:
            video_info['filename'] = os.path.basename(video_info['path'])
        else:
            video_info['filename'] = 'No file'
    
    return render_template('admin_videos.html', 
                         all_videos=all_videos,
                         all_step_data=all_step_data,
                         steps=range(1, 5))

@app.route('/admin/how-it-works/upload-video/<int:step>', methods=['POST'])
@login_required
def upload_how_it_works_video(step):
    """Upload video for a specific step"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    if step < 1 or step > 4:
        return jsonify({'success': False, 'error': 'Invalid step number'})
    
    video_file = request.files.get('video')
    thumbnail_file = request.files.get('thumbnail')
    
    if not video_file:
        return jsonify({'success': False, 'error': 'No video file provided'})
    
    result = video_manager.upload_video(step, video_file, thumbnail_file)
    
    if result['success']:
        flash(f'Video uploaded successfully for Step {step}!', 'success')
        return jsonify({
            'success': True,
            'message': 'Video uploaded successfully',
            'video_url': result.get('video_path'),
            'thumbnail_url': result.get('thumbnail_path')
        })
    else:
        return jsonify({'success': False, 'errors': result['errors']})

# ============================================================================
# DOWNLOAD ROUTES
# ============================================================================

@app.route('/download_csv/<event_id>/<form_id>')
@login_required
def download_csv(event_id, form_id):
    """Serve the form responses as a CSV file for the PDF generator"""
    # 1. Check if the user is authorized to see this data
    event = load_event(event_id)
    if not event or event.get('creator_id') != session.get('user_id'):
        return "Unauthorized", 403

    # 2. Define the path
    csv_path = os.path.join('data', 'events', event_id, f"{form_id}.csv")
    
    # 3. Handle missing files gracefully for the JavaScript fetch
    if not os.path.exists(csv_path):
        return "Timestamp,Response ID,Status\n", 200, {'Content-Type': 'text/csv'}

    try:
        # 4. Create the response
        response = make_response(send_file(
            csv_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'responses_{form_id}.csv'
        ))
        
        # 5. CRITICAL: Bypass ngrok warning so the PDF generator can read the data
        response.headers['ngrok-skip-browser-warning'] = 'true'
        return response
        
    except Exception as e:
        print(f"Error serving CSV: {e}")
        return "Error loading data", 500

@app.route('/download_file/<event_id>/<form_id>/<filename>')
@login_required
def download_file(event_id, form_id, filename):
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    file_path = f'static/uploads/events/{event_id}/{form_id}/{filename}'
    
    if not os.path.exists(file_path):
        flash('File not found!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    return send_file(file_path, as_attachment=True)

# Add this route to the PDF Generation section (around line 1700-1800 range)

# ============================================================================
# PDF GENERATION ROUTES
# ============================================================================

@app.route('/generate_pro_pdf/<event_id>/<form_id>')
@login_required
def generate_pro_pdf(event_id, form_id):
    """Generate professional PDF using csv_to_pdf.py and send to user"""
    try:
        # Check authorization
        event = load_event(event_id)
        if not event or event.get('creator_id') != session['user_id']:
            flash('Unauthorized!', 'error')
            return redirect(url_for('dashboard'))
        
        # Get form data
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            flash('Form not found!', 'error')
            return redirect(url_for('dashboard'))
        
        # Path to CSV file
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            flash('No response data available!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
        # Check if CSV has data
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            data = list(reader)
        
        if len(data) <= 1:
            flash('No responses available to generate report!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
        print(f"🔄 Generating professional PDF for {event['name']} - {form['title']}")
        
        # Run csv_to_pdf.py to generate the PDF
        import subprocess
        import sys
        
        # Build the command
        cmd = [
            sys.executable,
            'csv_to_pdf.py',
            '--single',
            csv_path,
            event['name'],
            form['title']
        ]
        
        print(f"🔧 Executing: {' '.join(cmd)}")
        
        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        # Check result
        if result.returncode != 0:
            print(f"❌ PDF generation failed:")
            print(f"   STDOUT: {result.stdout}")
            print(f"   STDERR: {result.stderr}")
            flash('Failed to generate PDF report!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
        # Parse output to find the generated PDF
        pdf_filename = None
        for line in result.stdout.split('\n'):
            if 'PDF_GENERATED:' in line:
                pdf_filename = line.split('PDF_GENERATED:')[1].strip()
                break
        
        if not pdf_filename:
            # Try alternative output format
            for line in result.stdout.split('\n'):
                if 'Generated:' in line:
                    pdf_filename = line.split('Generated:')[1].strip()
                    break
        
        if pdf_filename:
            # Build the full path
            pdf_path = os.path.join('reports', pdf_filename)
            
            if os.path.exists(pdf_path):
                print(f"✅ PDF ready: {pdf_path}")
                
                # Send the file to user
                return send_file(
                    pdf_path,
                    as_attachment=True,
                    download_name=pdf_filename,
                    mimetype='application/pdf'
                )
        
        # If we couldn't find the PDF in output, look for the most recent PDF
        import glob
        from datetime import datetime
        
        # Look for PDFs in reports folder
        pdf_files = glob.glob('reports/*.pdf')
        
        if pdf_files:
            # Get the most recently created PDF
            pdf_files.sort(key=os.path.getctime, reverse=True)
            latest_pdf = pdf_files[0]
            
            print(f"📄 Found latest PDF: {latest_pdf}")
            
            return send_file(
                latest_pdf,
                as_attachment=True,
                download_name=os.path.basename(latest_pdf),
                mimetype='application/pdf'
            )
        
        flash('PDF generation failed - no output file created', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
    except subprocess.TimeoutExpired:
        flash('PDF generation timed out. The report might be too large.', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    except Exception as e:
        print(f"❌ Error in generate_pro_pdf: {str(e)}")
        flash(f'Error generating PDF: {str(e)[:100]}', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

# Also add the view_pro_pdf route if it's referenced in templates
@app.route('/view_pro_pdf/<event_id>/<form_id>')
@login_required
def view_pro_pdf(event_id, form_id):
    """View professional PDF with beautiful interface"""
    try:
        # Check authorization
        event = load_event(event_id)
        if not event or event.get('creator_id') != session['user_id']:
            flash('Unauthorized!', 'error')
            return redirect(url_for('dashboard'))
        
        # Get form data
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            flash('Form not found!', 'error')
            return redirect(url_for('dashboard'))
        
        # Path to CSV file
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            flash('No response data available!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
        # Get or generate PDF
        import glob
        import subprocess
        import sys
        
        # Look for existing PDFs
        safe_event_name = event['name'].replace(' ', '_')[:30]
        pattern = f"reports/{safe_event_name}*.pdf"
        existing_pdfs = glob.glob(pattern)
        
        if existing_pdfs:
            # Sort by modification time (newest first)
            existing_pdfs.sort(key=os.path.getmtime, reverse=True)
            latest_pdf = existing_pdfs[0]
            
            # Check if it's recent (less than 1 hour old)
            from datetime import datetime
            file_age = datetime.now().timestamp() - os.path.getmtime(latest_pdf)
            
            if file_age < 3600:  # Less than 1 hour
                pdf_filename = os.path.basename(latest_pdf)
                pdf_url = f'/get_pdf_file/{pdf_filename}'
                download_url = f'/download_pdf_file/{pdf_filename}'
                
                return render_template('view_pdf.html',
                                     pdf_url=pdf_url,
                                     pdf_filename=pdf_filename,
                                     download_url=download_url,
                                     event_name=event['name'],
                                     form_title=form['title'],
                                     event_id=event_id,
                                     form_id=form_id)
        
        # Generate new PDF
        cmd = [
            sys.executable,
            'csv_to_pdf.py',
            '--single',
            csv_path,
            event['name'],
            form['title']
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # Parse output for filename
            pdf_filename = None
            for line in result.stdout.split('\n'):
                if 'PDF_GENERATED:' in line:
                    pdf_filename = line.split('PDF_GENERATED:')[1].strip()
                    break
                elif 'Generated:' in line:
                    pdf_filename = line.split('Generated:')[1].strip()
                    break
            
            if pdf_filename:
                pdf_url = f'/get_pdf_file/{pdf_filename}'
                download_url = f'/download_pdf_file/{pdf_filename}'
                
                return render_template('view_pdf.html',
                                     pdf_url=pdf_url,
                                     pdf_filename=pdf_filename,
                                     download_url=download_url,
                                     event_name=event['name'],
                                     form_title=form['title'],
                                     event_id=event_id,
                                     form_id=form_id)
        
        flash('Failed to generate PDF!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
        
    except Exception as e:
        log_message(f"Error viewing PDF: {e}", "ERROR")
        flash(f'Error: {str(e)[:100]}', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

# Add these helper routes for PDF serving
@app.route('/get_pdf_file/<filename>')
@login_required
def get_pdf_file(filename):
    """Serve PDF file for viewing"""
    pdf_path = os.path.join('reports', filename)
    
    if not os.path.exists(pdf_path):
        flash('PDF not found!', 'error')
        return redirect(url_for('dashboard'))
    return send_file(pdf_path, mimetype='application/pdf')

@app.route('/download_pdf_file/<filename>')
@login_required
def download_pdf_file(filename):
    """Download PDF file"""
    pdf_path = os.path.join('reports', filename)
    
    if not os.path.exists(pdf_path):
        flash('PDF not found!', 'error')
        return redirect(url_for('dashboard'))
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

# Add these routes to the Download Routes section (around line 1900-2000 range)

# ============================================================================
# UPLOAD MANAGEMENT ROUTES
# ============================================================================

@app.route('/view_uploads/<event_id>/<form_id>')
@login_required
def view_uploads(event_id, form_id):
    """View uploaded files for a form"""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    upload_dir = f'static/uploads/events/{event_id}/{form_id}'
    files = []
    
    if os.path.exists(upload_dir):
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                files.append({
                    'name': filename,
                    'size': file_size,
                    'path': file_path,
                    'url': f'/download_file/{event_id}/{form_id}/{filename}'
                })
    
    return render_template('uploads.html', 
                         event=event, 
                         files=files,
                         event_id=event_id,
                         form_id=form_id)

# ============================================================================
# FEEDBACK MANAGEMENT ROUTES (if any are missing)
# ============================================================================

@app.route('/admin/get_feedback_detail/<feedback_id>')
@login_required
def get_feedback_detail(feedback_id):
    """Get detailed feedback information"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    feedback_data = load_feedback()
    feedback = next((fb for fb in feedback_data if fb['id'] == feedback_id), None)
    
    if feedback:
        return jsonify({'success': True, 'feedback': feedback})
    else:
        return jsonify({'success': False, 'error': 'Feedback not found'})
        
@app.route('/admin/update_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    """Update user information"""
    try:
        data = request.json
        
        users = load_users()
        
        if user_id not in users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Update user data
        if 'username' in data:
            users[user_id]['username'] = data['username']
        
        if 'email' in data:
            users[user_id]['email'] = data['email']
        
        if 'mobile' in data:
            users[user_id]['mobile'] = data['mobile']
        
        if 'is_admin' in data:
            users[user_id]['is_admin'] = data['is_admin']
        
        if 'email_verified' in data:
            users[user_id]['email_verified'] = data['email_verified']
        
        if 'new_password' in data and data['new_password']:
            users[user_id]['password'] = data['new_password']
        
        save_users(users)
        
        log_message(f"User {user_id} updated by admin: {session.get('username')}", "ADMIN")
        return jsonify({'success': True, 'message': 'User updated successfully'})
        
    except Exception as e:
        log_message(f"Error updating user: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# VIDEO DEBUG ROUTES (if referenced)
# ============================================================================

@app.route('/list-videos')
def list_videos():
    """List all available video files"""
    video_dir = 'static/videos/how-it-works'
    files = []
    
    if os.path.exists(video_dir):
        for filename in os.listdir(video_dir):
            filepath = os.path.join(video_dir, filename)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                mime_type, _ = mimetypes.guess_type(filepath)
                files.append({
                    'name': filename,
                    'size_mb': size / (1024*1024),
                    'mime_type': mime_type,
                    'path': filepath,
                    'url': f"/static/videos/how-it-works/{filename}"
                })
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Available Videos</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #4361ee; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .test-link { color: blue; text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Available Video Files</h1>
        <table>
            <tr>
                <th>Filename</th>
                <th>Size (MB)</th>
                <th>MIME Type</th>
                <th>Path</th>
                <th>Test Links</th>
            </tr>
    """
    
    for file in files:
        html += f"""
            <tr>
                <td>{file['name']}</td>
                <td>{file['size_mb']:.2f}</td>
                <td>{file['mime_type'] or 'Unknown'}</td>
                <td><code>{file['path']}</code></td>
                <td>
                    <a href="{file['url']}" target="_blank" class="test-link">Direct Link</a> |
                    <a href="{file['url']}" download class="test-link">Download</a>
                </td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Test All Steps:</h2>
        <ul>
            <li><a href="/how-it-works/step/1">Step 1 Page</a></li>
            <li><a href="/how-it-works/step/2">Step 2 Page</a></li>
            <li><a href="/how-it-works/step/3">Step 3 Page</a></li>
            <li><a href="/how-it-works/step/4">Step 4 Page</a></li>
        </ul>
    </body>
    </html>
    """
    
    return html

# ============================================================================
# MISCELLANEOUS ROUTES
# ============================================================================

@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('terms.html')
    
@app.route('/premium')
def premium():
    """Premium features and pricing page"""
    return render_template('premium.html')

@app.route('/privacy')
def privacy_policy():
    """Privacy Policy page"""
    return render_template('privacy_policy.html')

@app.route('/email_status/<batch_id>')
@login_required
def email_status(batch_id):
    """Get email batch status"""
    status = load_email_status(session['user_id'])
    
    if status and status.get('batch_id') == batch_id:
        return json.dumps(status, indent=2)
    else:
        return json.dumps({'error': 'Batch not found'})

@app.route('/clear_email_status')
@login_required
def clear_email_status():
    """Clear email status for current user"""
    status_file = f'data/email_status/{session["user_id"]}.json'
    if os.path.exists(status_file):
        os.remove(status_file)
    
    # Also clear session results
    if 'last_email_results' in session:
        session.pop('last_email_results')
    
    flash('Email status cleared.', 'info')
    return redirect(request.referrer or url_for('dashboard'))

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.after_request
def remove_whitespace(response):
    """Remove any whitespace before DOCTYPE to prevent Quirks Mode"""
    if response.content_type == 'text/html; charset=utf-8':
        content = response.get_data(as_text=True)
        content = content.lstrip()
        response.set_data(content)
    
    return response

# ============================================================================
# APP STARTUP
# ============================================================================

# Add this at the end of your app.py file, before socketio.run()
if __name__ == '__main__':
    with app.app_context():
        init_volunteer_system()
        # Create all database tables
        db.create_all()
        print("✅ Database tables created successfully!")
    print("="*80)
    print("🚀 EventFlow Application Starting...")
    print("="*80)
    print("📧 Email System Status:")
    print(f"   Username: {MAIL_USERNAME}")
    print(f"   Server: {MAIL_SERVER}:{MAIL_PORT}")
    print("="*80)
    print("🎬 Video System Status:")
    
    video_dir = 'static/videos/how-it-works'
    if os.path.exists(video_dir):
        files = os.listdir(video_dir)
        for file in files:
            filepath = os.path.join(video_dir, file)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath) / (1024*1024)
                print(f"   📁 {file} ({size:.1f} MB)")
    else:
        print("   ⚠️ Video directory not found!")
    
    print("="*80)
    print("📊 System Statistics:")
    stats = get_server_statistics()
    print(f"   👥 Users: {stats['users']}")
    print(f"   📅 Events: {stats['events']}")
    print(f"   📋 Forms: {stats['forms']}")
    print(f"   📝 Registrations: {stats['registrations']}")
    print("="*80)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
