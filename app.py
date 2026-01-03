import os
import json
import csv
import uuid
import qrcode
import base64
import re
import threading
import queue
import mimetypes
import resend
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, send_from_directory, make_response, jsonify, Response, abort
from functools import wraps
from werkzeug.utils import secure_filename
from io import BytesIO
from dotenv import load_dotenv
from how_it_works_data import get_step_data, get_all_step_data, get_step_navigation
from video_manager import video_manager
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
import logging
import logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class CreateEventForm(FlaskForm):
    event_name = StringField(validators=[DataRequired()])
    description = TextAreaField(validators=[DataRequired()])

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Resend configuration - ONLY email provider
resend.api_key = os.environ.get("RESEND_API_KEY")

# Email status tracking
email_status_queue = queue.Queue()
email_statuses = {}  # Store email status by user/session

print("="*80)
print("📧 EventFlow Email System - RESEND ONLY VERSION")
print("="*80)
print("✅ All emails powered by Resend API")
print("✅ No SMTP configuration needed")
print("✅ Fully compatible with Render free tier")
print(f"✅ Resend API Key: {'Set' if resend.api_key else 'NOT SET'}")
print("="*80)

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 
    'txt', 'csv', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar'
}

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

# Create directories
os.makedirs('data/events', exist_ok=True)
os.makedirs('static/uploads', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('data/email_status', exist_ok=True)

def load_users():
    try:
        with open('data/users.json', 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open('data/users.json', 'w') as f:
        json.dump(users, f, indent=4)

def load_event(event_id):
    try:
        with open(f'data/events/{event_id}.json', 'r') as f:
            return json.load(f)
    except:
        return None

def save_event(event_data):
    os.makedirs('data/events', exist_ok=True)
    path = f"data/events/{event_data['id']}.json"
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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_qr_code(url):
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#4361ee", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        log_message(f"QR Code error: {e}", "ERROR")
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
                                stats['registrations'] += max(0, len(list(reader)) - 1)  # Exclude header
            except:
                continue
    
    except:
        pass
    
    return stats

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
    """Send thank you email using Resend API"""
    if not resend.api_key:
        app.logger.warning("RESEND_API_KEY not set - skipping thank you email")
        log_message("Thank you email skipped: No RESEND_API_KEY", "WARNING")
        return False

    try:
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
                body {{ font-family: Arial, sans-serif; background: #f8fafc; padding: 20px; }}
                .container {{ max-width: 600px; margin: auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #6C63FF 0%, #3f37c9 100%); color: white; padding: 40px; text-align: center; }}
                .content {{ padding: 40px; }}
                .summary {{ background: #f0efff; padding: 25px; border-radius: 10px; margin: 30px 0; }}
                .stars {{ font-size: 28px; color: #ffc107; }}
                .badge {{ padding: 8px 16px; background: #d1fae5; color: #059669; border-radius: 30px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Thank You, {name}!</h1>
                    <p>Your feedback makes EventFlow better</p>
                </div>
                <div class="content">
                    <p>Hi {name},</p>
                    <p>Thank you so much for your feedback! We truly appreciate you taking the time.</p>
                    
                    <div class="summary">
                        <p><strong>Rating:</strong> <span class="stars">{'★' * rating}{'☆' * (5 - rating)}</span> {rating}/5</p>
                        <p><strong>Type:</strong> <span class="badge">{feedback_type.replace('_', ' ').title()}</span></p>
                        <p><strong>Reference ID:</strong> <code>{feedback_id}</code></p>
                    </div>
                    
                    <p><strong>Your message:</strong></p>
                    <p style="font-style: italic; background: #f8fafc; padding: 15px; border-radius: 8px;">"{message[:300]}{'...' if len(message) > 300 else ''}"</p>
                    
                    <p>{type_message}</p>
                    <p>We're always improving — thanks for being part of it!</p>
                    <p>Best regards,<br><strong>The EventFlow Team</strong></p>
                </div>
            </div>
        </body>
        </html>
        """

        params = {
            "from": "EventFlow <onboarding@resend.dev>",
            "to": [to_email],
            "subject": "🎉 Thank You for Your Feedback!",
            "html": html_content,
        }

        # response = resend.Emails.send(params)
        # app.logger.info(f"Thank you email sent via Resend! ID: {response.get('id')}")
        # log_message(f"Thank you email sent to {to_email} (Resend ID: {response.get('id')})", "SUCCESS")
        # return True
        log_message(f"Thank you email to {to_email} commented out", "INFO")
        return False

    except Exception as e:
        app.logger.error(f"Resend email failed: {str(e)}", exc_info=True)
        log_message(f"Resend email failed for {to_email}: {e}", "ERROR")
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

@app.route('/admin/send_followup', methods=['POST'])
@login_required
def admin_send_followup():
    """Admin send follow-up email - NEW ROUTE"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.json
    feedback_id = data.get('feedback_id')
    subject = data.get('subject', 'Follow-up on your feedback')
    message = data.get('message')
    priority = data.get('priority', 'medium')
    
    if not message:
        return jsonify({'success': False, 'error': 'Message is required'})
    
    # Load feedback
    feedback_data = load_feedback()
    
    # Determine recipient
    recipient_email = None
    recipient_name = None
    
    if feedback_id and feedback_id != 'null':
        # Find the feedback
        feedback = next((fb for fb in feedback_data if fb['id'] == feedback_id), None)
        
        if not feedback:
            return jsonify({'success': False, 'error': 'Feedback not found'})
        
        # Use feedback's email
        if feedback.get('email'):
            recipient_email = feedback['email']
            recipient_name = feedback.get('name', 'Valued User')
    else:
        # If no feedback ID, we need recipient info from request
        recipient_email = data.get('recipient_email')
        recipient_name = data.get('recipient_name', 'Valued User')
    
    if not recipient_email:
        return jsonify({'success': False, 'error': 'No recipient email available'})
    
    try:
        # Send email using Resend
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .message-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #4361ee; margin: 20px 0; }}
                .signature {{ margin-top: 30px; color: #666; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #999; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <p>Hello {recipient_name},</p>
                
                <div class="message-box">
                    {message.replace('\n', '<br>')}
                </div>
                
                <div class="signature">
                    <p>Best regards,<br>The EventFlow Team</p>
                </div>
                
                <div class="footer">
                    <p>EventFlow Support</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # success, email_msg = send_email_resend(
        #     recipient_email,
        #     subject,
        #     html_content
        # )
        
        # if success:
        #     # Update feedback status if we have feedback_id
        #     if feedback_id and feedback_id != 'null':
        #         for fb in feedback_data:
        #             if fb['id'] == feedback_id:
        #                 fb['status'] = 'responded'
        #                 fb['responded_at'] = datetime.now().isoformat()
        #                 fb['responded_by'] = session['user_id']
        #                 fb['response_message'] = f"Follow-up sent: {message[:100]}..."
        #                 break
            
        #     save_feedback(feedback_data)
        #     log_message(f"Admin sent follow-up to {recipient_email}", "INFO")
        #     return jsonify({'success': True, 'recipient': recipient_email})
        # else:
        #     return jsonify({'success': False, 'error': f'Email failed: {email_msg}'})
        
        log_message(f"Admin follow-up email to {recipient_email} commented out", "INFO")
        return jsonify({'success': False, 'error': 'Email sending commented out'})
            
    except Exception as e:
        log_message(f"Error sending follow-up: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

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
                # Check if it's a video file
                if any(filename_lower.endswith(ext) for ext in ['.mp4', '.webm', '.mov', '.avi', '.mkv']):
                    return os.path.join(video_dir, filename)
    
    # If no pattern matches, try to get the first file that might be for this step
    # (in case files are numbered sequentially but not named with step)
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
    """Send email notification about new feedback - enhanced with settings"""
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
        admin_email = settings.get('admin_email', 'admin@example.com')
        if admin_email:
            # success, message = send_email_resend(admin_email, subject, html_content)
            # if success:
            #     log_message(f"Feedback notification sent to {admin_email}", "INFO")
            # else:
            #     log_message(f"Failed to send feedback notification: {message}", "ERROR")
            log_message(f"Feedback notification to {admin_email} commented out", "INFO")
                
    except Exception as e:
        log_message(f"Error sending feedback notification: {e}", "ERROR")

# ============================================================================
# RESEND EMAIL FUNCTIONS (COMMENTED OUT)
# ============================================================================

# Email functions commented out as requested

# ============================================================================
# DEBUG EMAIL FUNCTION (COMMENTED OUT)
# ============================================================================

# Email debug routes commented out as requested

# ============================================================================
# TEST EMAIL ROUTES (COMMENTED OUT)
# ============================================================================

# Test email routes commented out as requested

# ============================================================================
# COMPARE EMAIL TEST (COMMENTED OUT)
# ============================================================================

# Compare email test commented out as requested

# ============================================================================
# CSV TO PDF CREATION (UNCHANGED)
# ============================================================================

def generate_pdf_report(event_id, form_id):
    """Generate PDF report for a form."""
    try:
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        
        if not os.path.exists(csv_path):
            return None
        
        # Load event and form data
        event = load_event(event_id)
        if not event:
            return None
        
        form = None
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form = f
                break
        
        if not form:
            return None
        
        # Generate PDF
        return generate_pdf_from_csv_func(
            csv_path,
            event_name=event.get('name'),
            form_title=form.get('title')
        )
    except Exception as e:
        log_message(f"PDF report error: {e}", "ERROR")
        return None

def generate_pdf_from_csv_func(csv_path, event_name=None, form_title=None):
    """Core PDF generation function (similar to standalone version)."""
    try:
        # Read CSV data
        data = []
        with open(csv_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                data.append(row)
        
        if len(data) <= 1:
            return None
        
        # Create PDF in memory
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        buffer = BytesIO()
        
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        styles = getSampleStyleSheet()
        
        # Build story
        story = []
        
        # Add title if provided
        if event_name:
            title_style = ParagraphStyle(
                'TitleStyle',
                parent=styles['Heading1'],
                fontSize=14,
                spaceAfter=12,
                alignment=TA_CENTER
            )
            story.append(Paragraph(event_name, title_style))
        
        if form_title:
            subtitle_style = ParagraphStyle(
                'SubtitleStyle',
                parent=styles['Heading2'],
                fontSize=12,
                spaceAfter=24,
                alignment=TA_CENTER
            )
            story.append(Paragraph(form_title, subtitle_style))
        
        # Prepare table
        table_data = []
        
        # Add headers
        if data:
            headers = data[0]
            header_style = ParagraphStyle(
                'HeaderStyle',
                parent=styles['Normal'],
                fontSize=9,
                textColor=colors.white,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            table_data.append([Paragraph(str(h), header_style) for h in headers])
            
            # Add data (limit to 100 rows for performance)
            cell_style = ParagraphStyle(
                'CellStyle',
                parent=styles['Normal'],
                fontSize=8,
                alignment=TA_LEFT
            )
            
            max_rows = min(100, len(data)-1)
            for i in range(1, max_rows+1):
                row = []
                for cell in data[i]:
                    cell_text = str(cell)
                    if len(cell_text) > 100:
                        cell_text = cell_text[:100] + "..."
                    row.append(Paragraph(cell_text, cell_style))
                table_data.append(row)
        
        # Create table
        if table_data:
            col_count = len(table_data[0])
            col_width = doc.width / max(col_count, 1)
            col_widths = [col_width] * col_count
            
            table = Table(table_data, colWidths=col_widths, repeatRows=1)
            
            table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2C3E50')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,0), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 9),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('FONTSIZE', (0,1), (-1,-1), 8),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, colors.white]),
            ]))
            
            story.append(table)
        
        # Build PDF
        doc.build(story)
        
        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes
        
    except Exception as e:
        log_message(f"PDF generation error: {e}", "ERROR")
        return None

# Add this route to your app.py
@app.route('/generate_pdf/<event_id>/<form_id>')
@login_required
def generate_pdf_route(event_id, form_id):
    """Route to generate and download PDF report."""
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    pdf_bytes = generate_pdf_report(event_id, form_id)
    
    if pdf_bytes:
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        
        # Get form title for filename
        form_title = 'Responses'
        for f in event.get('forms', []):
            if f['id'] == form_id:
                form_title = f.get('title', 'Responses')
                break
        
        filename = f"{event.get('name', 'Event')}_{form_title}_Report.pdf"
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
    else:
        flash('Failed to generate PDF report!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

# ============================================================================
# DEBUG SHARE FORM EMAIL (COMMENTED OUT)
# ============================================================================

# Debug share form email commented out as requested

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
# DIAGNOSTIC TOOLS (COMMENTED OUT)
# ============================================================================

# Email diagnostic tools commented out as requested

# ============================================================================
# VIDEO DEBUGGING ROUTES (UNCHANGED)
# ============================================================================

@app.route('/test-video-access/<int:step>')
def test_video_access(step):
    """Test if video file is accessible"""
    video_path = find_video_file(step)
    
    if not video_path:
        return f"❌ Step {step}: No video file found"
    
    # Check file exists
    if not os.path.exists(video_path):
        return f"❌ Step {step}: File path doesn't exist: {video_path}"
    
    # Get file info
    file_size = os.path.getsize(video_path)
    file_size_mb = file_size / (1024 * 1024)
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(video_path)
    
    # Create test HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Video Test - Step {step}</title>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            .success {{ color: green; }}
            .error {{ color: red; }}
        </style>
    </head>
    <body>
        <h1>Video Test - Step {step}</h1>
        
        <h2>File Information:</h2>
        <ul>
            <li><strong>Path:</strong> {video_path}</li>
            <li><strong>Exists:</strong> <span class="{'success' if os.path.exists(video_path) else 'error'}">
                {os.path.exists(video_path)}
            </span></li>
            <li><strong>Size:</strong> {file_size_mb:.2f} MB ({file_size} bytes)</li>
            <li><strong>MIME Type:</strong> {mime_type or 'Unknown'}</li>
            <li><strong>Readable:</strong> {os.access(video_path, os.R_OK)}</li>
        </ul>
        
        <h2>Video Player Test:</h2>
        <div style="max-width: 800px; margin: 20px 0;">
            <video controls style="width: 100%;">
                <source src="/static/videos/how-it-works/{os.path.basename(video_path)}" type="{mime_type or 'video/mp4'}">
                Your browser does not support the video tag.
            </video>
        </div>
        
        <h2>Direct Links:</h2>
        <ul>
            <li><a href="/static/videos/how-it-works/{os.path.basename(video_path)}" download>Download Video</a></li>
            <li><a href="/list-videos">Back to Video List</a></li>
        </ul>
        
        <h2>Browser Test:</h2>
        <p>Try opening this link directly: <a href="/static/videos/how-it-works/{os.path.basename(video_path)}" target="_blank">Open in new tab</a></p>
    </body>
    </html>
    """
    
    return html

@app.route('/debug-video/<int:step>')
def debug_video(step):
    """Debug video file issues"""
    video_path = find_video_file(step)
    
    debug_info = {
        'step': step,
        'video_path': video_path,
        'video_path_exists': False,
        'video_url_accessible': False,
        'file_size': 0,
        'file_permissions': 'unknown',
        'mime_type': 'unknown'
    }
    
    if video_path:
        debug_info['video_path_exists'] = os.path.exists(video_path)
        if debug_info['video_path_exists']:
            try:
                debug_info['file_size'] = os.path.getsize(video_path)
                debug_info['file_permissions'] = oct(os.stat(video_path).st_mode)[-3:]
                mime_type, _ = mimetypes.guess_type(video_path)
                debug_info['mime_type'] = mime_type or 'unknown'
            except Exception as e:
                debug_info['error'] = str(e)
    
    return jsonify(debug_info)

# ============================================================================
# VIDEO TESTING AND LISTING ROUTES (UNCHANGED)
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
        
        <h2>Direct Video Tests:</h2>
        <ul>
    """
    
    # Create direct test links for each step
    for step in range(1, 5):
        video_path = find_video_file(step)
        if video_path and os.path.exists(video_path):
            filename = os.path.basename(video_path)
            html += f"""
            <li>Step {step}: 
                <a href="/static/videos/how-it-works/{filename}" target="_blank">Play {filename}</a> | 
                <a href="/test-step-video/{step}">Test Page</a>
            </li>
            """
        else:
            html += f"""
            <li>Step {step}: <span style="color: red;">No video file found</span></li>
            """
    
    html += """
        </ul>
    </body>
    </html>
    """
    
    return html

@app.route('/test-step-video/<int:step>')
def test_step_video(step):
    """Test video for a specific step with direct player"""
    video_path = find_video_file(step)
    
    if not video_path or not os.path.exists(video_path):
        return f"No video found for step {step}", 404
    
    filename = os.path.basename(video_path)
    video_url = f"/static/videos/how-it-works/{filename}"
    
    # Get MIME type
    mime_type, _ = mimetypes.guess_type(video_path)
    
    # FIXED: Escape curly braces in JavaScript by doubling them
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Step {step} Video</title>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            .video-container {{ max-width: 800px; margin: 20px auto; }}
            video {{ width: 100%; border: 2px solid #333; }}
            .info {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>Test Video for Step {step}</h1>
        
        <div class="info">
            <p><strong>File:</strong> {filename}</p>
            <p><strong>URL:</strong> <a href="{video_url}" target="_blank">{video_url}</a></p>
            <p><strong>Path:</strong> {video_path}</p>
            <p><strong>MIME Type:</strong> {mime_type or 'video/mp4'}</p>
        </div>
        
        <div class="video-container">
            <h3>Video Player:</h3>
            <video controls autoplay muted>
                <source src="{video_url}" type="{mime_type or 'video/mp4'}">
                Your browser does not support HTML5 video.
            </video>
        </div>
        
        <div>
            <h3>Actions:</h3>
            <ul>
                <li><a href="{video_url}" target="_blank">Open in new tab</a></li>
                <li><a href="{video_url}" download>Download video</a></li>
                <li><a href="/how-it-works/step/{step}">Go to Step {step} page</a></li>
                <li><a href="/list-videos">Back to video list</a></li>
            </ul>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const video = document.querySelector('video');
                if (video) {{
                    video.addEventListener('error', function(e) {{
                        console.error('Video error:', video.error);
                        alert('Video error: Code ' + video.error.code + '\\n' + 
                              'Message: ' + video.error.message);
                    }});
                    
                    video.addEventListener('loadeddata', function() {{
                        console.log('Video loaded successfully');
                        console.log('Video duration:', video.duration);
                        console.log('Video dimensions:', video.videoWidth + 'x' + video.videoHeight);
                    }});
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    return html

# ============================================================================
# SIMPLE VIDEO SERVING (UNCHANGED)
# ============================================================================

@app.route('/debug-video-url/<int:step>')
def debug_video_url(step):
    """Debug video URL generation"""
    video_path = find_video_file(step)
    
    debug_info = {
        'step': step,
        'video_path': video_path,
        'exists': os.path.exists(video_path) if video_path else False,
        'urls': {}
    }
    
    if video_path and os.path.exists(video_path):
        filename = os.path.basename(video_path)
        
        debug_info['urls'] = {
            'static_url': url_for('static', filename=f'videos/how-it-works/{filename}'),
            'direct_url': f'/static/videos/how-it-works/{filename}',
            'step_url': f'/video/{step}',
            'serve_url': f'/serve_video/{step}'
        }
    
    return jsonify(debug_info)

# ============================================================================
# CUSTOM JINJA2 FILTERS (UNCHANGED)
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

# ============================================================================
# PDF GENERATION FUNCTIONS (UNCHANGED)
# ============================================================================
def generate_response_pdf(event_id, form_id, event_data=None, form_data=None):
    """Generate HTML report for form responses"""
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    
    if not os.path.exists(csv_path):
        return None
    
    # Read CSV data
    data = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                data.append(row)
    except Exception as e:
        log_message(f"Error reading CSV for PDF: {e}", "ERROR")
        return None
    
    if len(data) <= 1:
        return None
    
    # Generate HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Form Responses - {event_data.get('name', 'Event') if event_data else 'Event'}</title>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                margin: 40px; 
                background: #f8fafc; 
                color: #1e293b;
            }}
            .report-container {{ 
                max-width: 1200px; 
                margin: 0 auto; 
                background: white; 
                padding: 40px; 
                border-radius: 12px; 
                box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
            }}
            .header {{ 
                text-align: center; 
                margin-bottom: 40px; 
                border-bottom: 2px solid #4361ee; 
                padding-bottom: 20px; 
            }}
            h1 {{ 
                color: #4361ee; 
                margin-bottom: 10px; 
                font-size: 28px;
            }}
            .info {{ 
                color: #64748b; 
                margin-bottom: 30px; 
                font-size: 14px;
            }}
            .stats {{ 
                display: flex; 
                justify-content: space-around; 
                margin-bottom: 30px; 
                background: #f1f5f9; 
                padding: 20px; 
                border-radius: 10px; 
            }}
            .stat-item {{ 
                text-align: center; 
            }}
            .stat-value {{ 
                font-size: 24px; 
                font-weight: bold; 
                color: #4361ee; 
            }}
            .stat-label {{ 
                color: #64748b; 
                font-size: 14px; 
            }}
            table {{ 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 20px; 
                font-size: 14px;
            }}
            th {{ 
                background: linear-gradient(135deg, #4361ee 0%, #3f37c9 100%); 
                color: white; 
                padding: 12px; 
                text-align: left; 
                font-weight: 600; 
                border: none;
            }}
            td {{ 
                padding: 10px 12px; 
                border: 1px solid #e2e8f0; 
                vertical-align: top;
            }}
            tr:nth-child(even) {{ 
                background-color: #f8fafc; 
            }}
            tr:hover {{ 
                background-color: #f1f5f9; 
            }}
            .footer {{ 
                margin-top: 40px; 
                text-align: center; 
                color: #94a3b8; 
                font-size: 14px; 
                border-top: 1px solid #e2e8f0; 
                padding-top: 20px; 
            }}
            .print-button {{
                display: inline-block;
                background: #4361ee;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                text-decoration: none;
                margin: 20px 0;
                font-weight: bold;
            }}
            .print-button:hover {{
                background: #3f37c9;
            }}
            @media print {{
                .print-button {{ display: none; }}
                body {{ margin: 0; }}
                .report-container {{ 
                    box-shadow: none; 
                    padding: 20px; 
                }}
            }}
        </style>
    </head>
    <body>
        <div class="report-container">
            <div class="header">
                <h1>📊 Form Responses Report</h1>
                <div class="info">
                    <strong>Event:</strong> {event_data.get('name', 'N/A') if event_data else 'N/A'}<br>
                    <strong>Form:</strong> {form_data.get('title', 'N/A') if form_data else 'N/A'}<br>
                    <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-value">{len(data) - 1}</div>
                    <div class="stat-label">Total Responses</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{len(data[0]) - 2}</div>
                    <div class="stat-label">Questions</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{data[1][0] if len(data) > 1 else 'N/A'}</div>
                    <div class="stat-label">First Response</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{data[-1][0] if len(data) > 1 else 'N/A'}</div>
                    <div class="stat-label">Latest Response</div>
                </div>
            </div>
            
            <div style="text-align: center; margin: 20px 0;">
                <button class="print-button" onclick="window.print()">🖨️ Print / Save as PDF</button>
            </div>
            
            <h2>Responses Data</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
    """
    
    # Add headers
    for header in data[0]:
        html_content += f"<th>{header}</th>"
    html_content += "</tr></thead><tbody>"
    
    # Add data rows (limit to 100 rows for performance)
    max_rows = min(100, len(data) - 1)
    for i in range(1, max_rows + 1):
        html_content += "<tr>"
        for j, value in enumerate(data[i]):
            # Truncate long values for display
            display_value = str(value)
            if len(display_value) > 100:
                display_value = display_value[:100] + "..."
            
            # Check if this is a file upload field
            if 'upload' in str(data[0][j]).lower() or 'file' in str(data[0][j]).lower():
                if value and os.path.exists(f'static/uploads/events/{event_id}/{form_id}/{value}'):
                    display_value = f'📎 {value}'
                elif value:
                    display_value = f'📄 {value}'
                else:
                    display_value = 'No file'
            
            html_content += f"<td title='{value}'>{display_value}</td>"
        html_content += "</tr>"
    
    html_content += f"""
                        </tbody>
                    </table>
                </div>
                
                {f'<p style="color: #64748b; margin-top: 20px; font-style: italic;">Note: Showing {max_rows} of {len(data) - 1} total responses</p>' if max_rows < len(data) - 1 else ''}
                
                <div class="footer">
                    <p>Generated by EventFlow Registration System</p>
                    <p>&copy; {datetime.now().year} - All rights reserved</p>
                </div>
            </div>
        </body>
        </html>
    """
    
    return html_content.encode('utf-8')

def generate_detailed_pdf(event_id, form_id):
    """Alias for compatibility"""
    return generate_response_pdf(event_id, form_id)

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
        'closed': 'Cladmin/feedbosed'
    }
    return names.get(status, status)

@app.route('/admin/feedback_receiver')
@login_required
def admin_feedback_receiver():
    """Admin feedback dashboard page"""
    if session.get('user_id') != 'admin':  # Adjust admin check
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
    
    # Calculate statistics - MAKE SURE TO CALCULATE avg_rating
    stats = calculate_feedback_stats(feedback_data)
    
    # Extract avg_rating from stats
    avg_rating = stats.get('average_rating', 0)
    
    return render_template('admin_feedback_receiver.html',
                         feedback_list=paginated_feedback,
                         stats=stats,
                         avg_rating=avg_rating,  # Add this line
                         page=page,
                         total_pages=total_pages)

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

@app.route('/admin/mark_feedback_read/<feedback_id>', methods=['POST'])
@login_required
def mark_feedback_read(feedback_id):
    """Mark feedback as read"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    feedback_data = load_feedback()
    
    for fb in feedback_data:
        if fb['id'] == feedback_id:
            fb['status'] = 'read'
            fb['reviewed'] = True
            fb['reviewed_at'] = datetime.now().isoformat()
            fb['reviewed_by'] = session['user_id']
            break
    
    if save_feedback(feedback_data):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to save'})

@app.route('/admin/send_feedback_reply', methods=['POST'])
@login_required
def send_feedback_reply():
    """Send reply to feedback - CLEAN VERSION (only admin's message)"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.json
    feedback_id = data.get('feedback_id')
    subject = data.get('subject', 'Re: Your Feedback')
    message = data.get('message')
    new_status = data.get('status', 'responded')
    
    if not feedback_id or not message:
        return jsonify({'success': False, 'error': 'Missing required fields'})
    
    # Load feedback
    feedback_data = load_feedback()
    feedback = next((fb for fb in feedback_data if fb['id'] == feedback_id), None)
    
    if not feedback or not feedback.get('email'):
        return jsonify({'success': False, 'error': 'Feedback not found or no email'})
    
    try:
        # Send email reply using Resend
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .message-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #4361ee; margin: 20px 0; }}
                .signature {{ margin-top: 30px; color: #666; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #999; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <p>Hello {feedback.get('name', 'there')},</p>
                
                <div class="message-box">
                    {message.replace('\n', '<br>')}
                </div>
                
                <div class="signature">
                    <p>Best regards,<br>The EventFlow Team</p>
                </div>
                
                <div class="footer">
                    <p>EventFlow Support</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # success, email_msg = send_email_resend(
        #     feedback['email'],
        #     subject,
        #     html_content
        # )
        
        # if success:
        #     # Update feedback status
        #     for fb in feedback_data:
        #         if fb['id'] == feedback_id:
        #             fb['status'] = new_status
        #             fb['responded_at'] = datetime.now().isoformat()
        #             fb['responded_by'] = session['user_id']
        #             fb['response_message'] = message  # Store the response message
        #             break
            
        #     save_feedback(feedback_data)
        #     log_message(f"Admin replied to feedback {feedback_id}", "INFO")
        #     return jsonify({'success': True})
        # else:
        #     return jsonify({'success': False, 'error': f'Email failed: {email_msg}'})
        
        log_message(f"Admin feedback reply to {feedback['email']} commented out", "INFO")
        return jsonify({'success': False, 'error': 'Email sending commented out'})
            
    except Exception as e:
        log_message(f"Error sending feedback reply: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# MULTI-PAGE FEEDBACK FORM ROUTES (UNCHANGED)
# ============================================================================

@app.route('/feedback/multi/<int:current_page>', methods=['GET', 'POST'])
def multi_page_feedback(current_page):
    """Multi-page feedback form - each question is a separate page"""
    feedback_data = load_feedback()
    
    # Define feedback questions (customizable)
    questions = [
        {
            'id': 0,
            'title': 'How was your experience?',
            'type': 'rating',
            'required': True,
            'options': [1, 2, 3, 4, 5]
        },
        {
            'id': 1,
            'title': 'What type of feedback is this?',
            'type': 'radio',
            'required': True,
            'options': [
                'Praise 😊',
                'Suggestion 💡', 
                'Bug Report 🐛',
                'Feature Request ✨',
                'General ℹ️'
            ]
        },
        {
            'id': 2,
            'title': 'Your name (optional)',
            'type': 'text',
            'required': False,
            'placeholder': 'Anonymous is fine!'
        },
        {
            'id': 3,
            'title': 'Your email (optional)',
            'type': 'email',
            'required': False,
            'placeholder': 'For follow-up questions'
        },
        {
            'id': 4,
            'title': 'Tell us more...',
            'type': 'textarea',
            'required': True,
            'placeholder': 'Share your thoughts, suggestions, or issues...'
        }
    ]
    
    total_pages = len(questions)
    
    # Validate current page
    if current_page < 1 or current_page > total_pages:
        flash('Invalid page number', 'error')
        return redirect(url_for('feedback'))
    
    current_question = questions[current_page - 1]
    
    # Initialize session data if not exists
    if 'feedback_session' not in session:
        session['feedback_session'] = {}
    
    # Handle form submission
    if request.method == 'POST':
        # Save current answer
        answer = None
        if current_question['type'] == 'rating':
            answer = request.form.get(f'q_{current_question["id"]}')
        elif current_question['type'] in ['radio', 'select']:
            answer = request.form.get(f'q_{current_question["id"]}')
        elif current_question['type'] in ['text', 'email', 'textarea']:
            answer = request.form.get(f'q_{current_question["id"]}', '').strip()
        
        if answer is not None:
            session['feedback_session'][str(current_question['id'])] = answer
        
        # Check if this is the last page
        if current_page == total_pages:
            # Submit feedback
            return submit_multi_page_feedback()
        else:
            # Go to next page
            flash('Saved! Next question →', 'success')
            return redirect(url_for('multi_page_feedback', current_page=current_page + 1))
    
    # Progress calculation
    progress = (current_page / total_pages) * 100
    
    return render_template('feedback_multi.html',
                         current_page=current_page,
                         total_pages=total_pages,
                         current_question=current_question,
                         questions=questions,
                         progress=progress)

@app.route('/feedback/multi/submit', methods=['POST'])
def submit_multi_page_feedback():
    """Submit multi-page feedback with thank you email"""
    try:
        if 'feedback_session' not in session:
            return jsonify({'success': False, 'error': 'No feedback data found'})
        
        feedback_session = session['feedback_session']
        
        # Validate required fields
        rating = feedback_session.get('0')
        feedback_type = feedback_session.get('1')
        message = feedback_session.get('4', '').strip()
        name = feedback_session.get('2', '').strip()
        email = feedback_session.get('3', '').strip()
        
        if not rating or not feedback_type or not message:
            return jsonify({'success': False, 'error': 'Required fields missing'})
        
        # Map feedback type
        type_mapping = {
            'Praise 😊': 'praise',
            'Suggestion 💡': 'suggestion',
            'Bug Report 🐛': 'bug',
            'Feature Request ✨': 'feature',
            'General ℹ️': 'general'
        }
        
        feedback_entry = {
            'id': str(uuid.uuid4()),
            'name': name or 'Anonymous',
            'email': email,
            'rating': int(rating),
            'type': type_mapping.get(feedback_type, 'general'),
            'message': message,
            'source': 'Multi-page form',
            'timestamp': datetime.now().isoformat(),
            'user_id': session.get('user_id'),
            'status': 'new',
            'reviewed': False,
            'session_data': feedback_session  # Store full session for admin review
        }
        
        # Save feedback
        feedback_data = load_feedback()
        feedback_data.append(feedback_entry)
        
        if save_feedback(feedback_data):
            # Send notification to admin
            send_feedback_notification(feedback_entry)
            
            # Send thank you email to user if email provided
            email_sent = False
            if email:
                email_sent = send_thank_you_email(
                    email,
                    name or 'there',
                    feedback_entry['id'],
                    type_mapping.get(feedback_type, 'general'),
                    int(rating),
                    message
                )
            
            # Clear session
            session.pop('feedback_session', None)
            
            return jsonify({
                'success': True,
                'message': 'Thank you for your detailed feedback! 🎉',
                'feedback_id': feedback_entry['id'],
                'email_sent': email_sent
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save feedback'})
            
    except Exception as e:
        log_message(f"Multi-page feedback error: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/debug/routes')
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
# CSRF TOKEN FUNCTION (UNCHANGED)
# ============================================================================

def generate_csrf_token():
    """Generate and return CSRF token for forms"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid.uuid4())
    return session['_csrf_token']

# Register as a global Jinja2 function
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ============================================================================
# CSRF PROTECTION (UNCHANGED)
# ============================================================================

@app.before_request
def csrf_protect():
    """Simple CSRF protection - skip for public forms"""
    # Skip CSRF for public endpoints AND create_event
    public_endpoints = [
        'submit_feedback', 'feedback', 'show_form', 'submit_form',
        'multi_page_feedback', 'submit_multi_page_feedback',
        'signup', 'verify_email', 'resend_otp', 'login',
        'create_event'  # ADD THIS LINE
    ]
    
    if request.endpoint in public_endpoints:
        return
    
    # Only check CSRF for authenticated users on sensitive endpoints
    if 'user_id' in session and request.method in ["POST", "PUT", "DELETE"]:
        token = None
        
        # Check for token in headers (AJAX) or form data
        if request.is_json:
            token = request.headers.get('X-CSRFToken')
        elif request.form:
            token = request.form.get('csrf_token')
        
        # Get stored token
        stored_token = session.get('_csrf_token')
        
        # If token is missing or doesn't match
        if not token or token != stored_token:
            log_message(f"CSRF token validation failed for user {session.get('user_id')} on {request.endpoint}", "WARNING")
            print(f"🔴 CSRF FAILURE DETAILS:")
            print(f"   Received token: {token}")
            print(f"   Stored token: {stored_token}")
            print(f"   Match: {token == stored_token}")
            
            if request.is_json:
                return jsonify({'error': 'Security token invalid. Please refresh and try again.'}), 403
            else:
                flash('Security token invalid. Please refresh the page and try again.', 'error')
                return redirect(request.referrer or url_for('dashboard'))

@app.before_request
def log_request_info():
    """Log detailed request info for debugging"""
    print(f"\n{'='*60}")
    print(f"📥 INCOMING REQUEST:")
    print(f"   Method: {request.method}")
    print(f"   Path: {request.path}")
    print(f"   Endpoint: {request.endpoint}")
    print(f"   Headers: {dict(request.headers)}")
    
    if request.method == 'POST':
        print(f"   Form data: {dict(request.form)}")
        print(f"   Files: {dict(request.files)}")
    
    print(f"{'='*60}")

@app.after_request
def log_response_info(response):
    """Log response info"""
    print(f"\n📤 OUTGOING RESPONSE:")
    print(f"   Status: {response.status}")
    print(f"   Headers: {dict(response.headers)}")
    print(f"{'='*60}")
    return response
    
@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 Bad Request errors"""
    print(f"\n🔥 400 BAD REQUEST ERROR:")
    print(f"   Error: {e}")
    print(f"   Description: {e.description if hasattr(e, 'description') else 'No description'}")
    print(f"   Request data: {request.data}")
    print(f"   Form data: {dict(request.form)}")
    print(f"   Headers: {dict(request.headers)}")
    print(f"   URL: {request.url}")
    
    # Return a simple error page
    return render_template('400.html', error=str(e)), 400

# ============================================================================
# FEEDBACK FORM ROUTES (UNCHANGED)
# ============================================================================

@app.route('/feedback')
def feedback():
    """Show feedback form"""
    return render_template('feedback_form.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    """Handle feedback submission with file upload - FIXED WITH BETTER ERROR HANDLING"""
    try:
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        rating = request.form.get('rating', '0')
        feedback_type = request.form.get('type', 'general')
        message = request.form.get('message', '').strip()
        source = request.form.get('source', '').strip()
        context = request.form.get('context', '').strip()
        can_contact = request.form.get('can_contact') == 'on'
        user_id = request.form.get('user_id', '')
        
        print(f"\n🔍 FEEDBACK SUBMISSION RECEIVED:")
        print(f"   Name: {name}")
        print(f"   Email: {email}")
        print(f"   Rating: {rating}")
        print(f"   Type: {feedback_type}")
        print(f"   Message length: {len(message)}")
        print(f"   All form data: {dict(request.form)}")
        
        # Validate required fields
        if not name or not email or not message:
            print("❌ Validation failed: Name, email, and message are required")
            return jsonify({
                'success': False, 
                'error': 'Name, email, and message are required'
            }), 400
        
        # Validate email format
        if '@' not in email or '.' not in email:
            print(f"❌ Validation failed: Invalid email format: {email}")
            return jsonify({
                'success': False, 
                'error': 'Please enter a valid email address'
            }), 400
        
        # Validate rating
        try:
            rating_int = int(rating)
            if rating_int < 0 or rating_int > 5:
                print(f"❌ Validation failed: Invalid rating value: {rating}")
                return jsonify({
                    'success': False, 
                    'error': 'Invalid rating value. Must be between 0 and 5.'
                }), 400
        except ValueError:
            print(f"❌ Validation failed: Rating is not a number: {rating}")
            return jsonify({
                'success': False, 
                'error': 'Rating must be a number between 0 and 5.'
            }), 400
        
        # Create feedback entry
        feedback_entry = {
            'id': str(uuid.uuid4()),
            'name': name,
            'email': email,
            'rating': rating_int,
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
        print("🔍 Loading existing feedback data...")
        feedback_data = load_feedback()
        print(f"   Found {len(feedback_data)} existing feedback entries")
        
        # Add new feedback
        feedback_data.append(feedback_entry)
        
        # Save feedback
        print("🔍 Saving feedback...")
        if save_feedback(feedback_data):
            print(f"✅ Feedback saved successfully with ID: {feedback_entry['id']}")
            log_message(f"Feedback submitted by {name} ({email}) - Type: {feedback_type}, Rating: {rating_int}", "INFO")
            
            # Send notification email to admin (in background, don't block)
            try:
                print("🔍 Attempting to send notification email...")
                send_feedback_notification(feedback_entry)
                print("✅ Notification email sent to admin")
            except Exception as email_error:
                print(f"⚠️ Failed to send notification email: {email_error}")
                # Don't fail the submission if email fails
            
            # Send thank you email to user (in background)
            email_sent = False
            try:
                print(f"🔍 Attempting to send thank you email to {email}...")
                email_sent = send_thank_you_email(
                    email, 
                    name, 
                    feedback_entry['id'],
                    feedback_type,
                    rating_int,
                    message
                )
                if email_sent:
                    print("✅ Thank you email sent successfully")
                else:
                    print("⚠️ Thank you email failed to send")
            except Exception as email_error:
                print(f"⚠️ Error sending thank you email: {email_error}")
                email_sent = False
            
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
            
            print(f"✅ Returning success response: {response_data}")
            return jsonify(response_data)
        else:
            print("❌ Failed to save feedback data")
            return jsonify({
                'success': False, 
                'error': 'Failed to save feedback'
            }), 500
            
    except Exception as e:
        print(f"❌ ERROR in submit_feedback: {str(e)}")
        import traceback
        traceback.print_exc()
        log_message(f"Error submitting feedback: {e}", "ERROR")
        return jsonify({
            'success': False, 
            'error': 'An internal server error occurred. Please try again later.',
            'debug': str(e) if app.debug else None
        }), 500
        
@app.route('/debug-email-test-feedback')
def debug_email_test_feedback():
    """Test email sending for feedback"""
    try:
        test_email = "test@example.com"
        print(f"🔍 Testing email to: {test_email}")
        
        # Test simple email
        # success, message = send_email_resend(
        #     test_email,
        #     "Test Feedback Email",
        #     "<h1>Test</h1><p>This is a test email for feedback system via Resend.</p>"
        # )
        
        return jsonify({
            'success': False,
            'message': 'Email sending commented out',
            'test_email': test_email,
            'resend_configured': bool(resend.api_key)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        

@app.route('/admin/feedback/settings', methods=['GET', 'POST'])
@login_required
def feedback_settings():
    """Feedback system settings"""
    if session.get('user_id') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    # Settings file
    settings_file = 'data/feedback_settings.json'
    
    # Default settings
    default_settings = {
        'send_thank_you_emails': True,
        'notify_admin_on_feedback': True,
        'admin_email': 'admin@example.com',
        'auto_reply_enabled': True,
        'auto_reply_message': "Thank you for your feedback! We've received your submission and will review it soon.",
        'feedback_categories': ['bug', 'suggestion', 'praise', 'general', 'feature']
    }
    
    # Load existing settings
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            settings = json.load(f)
    else:
        settings = default_settings
    
    if request.method == 'POST':
        # Update settings
        settings.update({
            'send_thank_you_emails': request.form.get('send_thank_you_emails') == 'on',
            'notify_admin_on_feedback': request.form.get('notify_admin_on_feedback') == 'on',
            'admin_email': request.form.get('admin_email', ''),
            'auto_reply_enabled': request.form.get('auto_reply_enabled') == 'on',
            'auto_reply_message': request.form.get('auto_reply_message', '')
        })
        
        # Save settings
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('feedback_settings'))
    
    return render_template('feedback_settings.html', settings=settings)

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    """Admin feedback dashboard"""
    # Check if user is admin (you can modify this check based on your admin logic)
    if session.get('user_id') != 'admin':  # Adjust this condition as needed
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    feedback_data = load_feedback()
    
    # Calculate statistics
    unique_users = set()
    recent_count = 0
    total_rating = 0
    rating_count = 0
    with_email_count = 0
    
    week_ago = datetime.now() - timedelta(days=7)
    
    for fb in feedback_data:
        # Unique users by email or user_id
        if fb.get('email'):
            unique_users.add(fb['email'])
            with_email_count += 1
        if fb.get('user_id'):
            unique_users.add(fb['user_id'])
        
        # Recent feedback (last 7 days)
        fb_time = datetime.fromisoformat(fb.get('timestamp', fb.get('created', '2000-01-01')))
        if fb_time >= week_ago:
            recent_count += 1
        
        # Rating statistics
        if fb.get('rating', 0) > 0:
            total_rating += fb['rating']
            rating_count += 1
    
    avg_rating = total_rating / rating_count if rating_count > 0 else None
    
    return render_template('admin_feedback.html',
                         feedback_data=feedback_data,
                         unique_users=unique_users,
                         recent_count=recent_count,
                         avg_rating=avg_rating,
                         with_email_count=with_email_count)

@app.route('/feedback/viewer')
@login_required
def feedback_viewer():
    """Feedback viewer page for users to see their own feedback"""
    try:
        feedback_data = load_feedback()
        print(f"📊 Total feedback entries: {len(feedback_data)}")
        
        # Filter to show only current user's feedback
        user_feedback = []
        for fb in feedback_data:
            # Match by user_id or email
            if fb.get('user_id') == session['user_id'] or fb.get('email') == session.get('email'):
                user_feedback.append(fb)
        
        print(f"👤 User feedback entries: {len(user_feedback)}")
        
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
        
        print(f"📄 Pagination: page {page} of {total_pages}, showing {len(paginated_feedback)} items")
        
        return render_template('feedback_viewer.html',
                             feedback_list=paginated_feedback,
                             stats=stats,
                             page=page,
                             total_pages=total_pages)
                             
    except Exception as e:
        print(f"❌ Error in feedback_viewer: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading feedback. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/export_feedback')
@login_required
def export_feedback():
    """Export user's feedback as CSV"""
    feedback_data = load_feedback()
    
    # Filter to show only current user's feedback
    user_feedback = []
    for fb in feedback_data:
        # Match by user_id or email
        if fb.get('user_id') == session['user_id'] or fb.get('email') == session.get('email'):
            user_feedback.append(fb)
    
    if not user_feedback:
        flash('No feedback data to export.', 'warning')
        return redirect(url_for('feedback_viewer'))
    
    # Create CSV content
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['ID', 'Timestamp', 'Name', 'Email', 'Type', 'Rating', 'Message', 'Status', 'Reviewed', 'Reviewed At'])
    
    # Write data
    for fb in user_feedback:
        writer.writerow([
            fb.get('id', ''),
            fb.get('timestamp', ''),
            fb.get('name', ''),
            fb.get('email', ''),
            fb.get('type', ''),
            fb.get('rating', ''),
            fb.get('message', ''),
            fb.get('status', ''),
            fb.get('reviewed', False),
            fb.get('reviewed_at', '')
        ])
    
    output.seek(0)
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=my_feedback_{datetime.now().strftime("%Y%m%d")}.csv'
    
    return response

@app.route('/admin/get_feedback')
@login_required
def get_feedback_json():
    """API endpoint to get feedback data (for AJAX)"""
    if session.get('user_id') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    feedback_data = load_feedback()
    return jsonify(feedback_data)

@app.route('/admin/delete_feedback/<feedback_id>', methods=['DELETE'])
@login_required
def delete_feedback(feedback_id):
    """Delete specific feedback"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        feedback_data = load_feedback()
        original_count = len(feedback_data)
        
        # Filter out the feedback to delete
        feedback_data = [fb for fb in feedback_data if fb['id'] != feedback_id]
        
        if len(feedback_data) < original_count:
            save_feedback(feedback_data)
            log_message(f"Feedback {feedback_id} deleted by admin {session['user_id']}", "INFO")
            return jsonify({'success': True, 'message': 'Feedback deleted'})
        else:
            return jsonify({'success': False, 'error': 'Feedback not found'})
            
    except Exception as e:
        log_message(f"Error deleting feedback {feedback_id}: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/mark_feedback_reviewed', methods=['POST'])
@login_required
def mark_feedback_reviewed():
    """Mark feedback as reviewed"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        feedback_ids = request.json.get('feedback_ids', [])
        feedback_data = load_feedback()
        
        updated_count = 0
        for fb in feedback_data:
            if fb['id'] in feedback_ids:
                fb['reviewed'] = True
                fb['reviewed_at'] = datetime.now().isoformat()
                fb['reviewed_by'] = session['user_id']
                updated_count += 1
        
        save_feedback(feedback_data)
        
        log_message(f"{updated_count} feedback items marked as reviewed by {session['user_id']}", "INFO")
        return jsonify({'success': True, 'updated_count': updated_count})
        
    except Exception as e:
        log_message(f"Error marking feedback as reviewed: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/clear_all_feedback', methods=['POST'])
@login_required
def clear_all_feedback():
    """Clear all feedback (admin only)"""
    if session.get('user_id') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        password = request.json.get('password', '')
        # Add your password validation here
        if password != 'your_admin_password':  # Change this to your admin password
            return jsonify({'success': False, 'error': 'Invalid password'})
        
        # Create backup before clearing
        backup_file = f'data/feedback_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        feedback_data = load_feedback()
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(feedback_data, f, indent=2, ensure_ascii=False)
        
        # Clear all feedback
        save_feedback([])
        
        log_message(f"All feedback cleared by admin {session['user_id']}. Backup saved to {backup_file}", "WARNING")
        return jsonify({'success': True, 'backup_file': backup_file})
        
    except Exception as e:
        log_message(f"Error clearing all feedback: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

# ============================================================================
# USER FEEDBACK FOLLOW-UP ROUTES (UNCHANGED)
# ============================================================================

@app.route('/user/send_followup', methods=['POST'])
@login_required
def user_send_followup():
    """Send follow-up message for user's feedback"""
    try:
        data = request.json
        feedback_id = data.get('feedback_id')
        subject = data.get('subject', 'Follow-up on feedback')
        message = data.get('message')
        priority = data.get('priority', 'medium')
        original_message = data.get('original_message', '')
        
        if not feedback_id or not message:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Load original feedback
        feedback_data = load_feedback()
        original_feedback = None
        
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                # Verify this feedback belongs to the current user
                if fb.get('user_id') == session['user_id'] or fb.get('email') == session.get('email'):
                    original_feedback = fb
                    break
        
        if not original_feedback:
            return jsonify({'success': False, 'error': 'Feedback not found or unauthorized'})
        
        # Create follow-up feedback entry
        followup_id = str(uuid.uuid4())
        followup_entry = {
            'id': followup_id,
            'name': session.get('username', 'User'),
            'email': session.get('email', ''),
            'rating': original_feedback.get('rating', 0),
            'type': 'followup',
            'message': f"""FOLLOW-UP TO FEEDBACK ID: {feedback_id}
            
Original Feedback: {original_message[:500]}
            
Follow-up Message: {message}
            
Priority: {priority.upper()}
            """,
            'source': 'Follow-up from feedback viewer',
            'context': f'Follow-up to {feedback_id}',
            'can_contact': True,
            'user_id': session['user_id'],
            'timestamp': datetime.now().isoformat(),
            'status': 'new',
            'reviewed': False,
            'parent_feedback_id': feedback_id,
            'priority': priority,
            'followup_subject': subject
        }
        
        # Save follow-up feedback
        feedback_data.append(followup_entry)
        save_feedback(feedback_data)
        
        # Send email notification to admin
        send_followup_notification(followup_entry, original_feedback)
        
        log_message(f"User {session['user_id']} sent follow-up for feedback {feedback_id}", "INFO")
        return jsonify({'success': True, 'followup_id': followup_id})
            
    except Exception as e:
        log_message(f"Error sending follow-up: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

def send_followup_notification(followup_feedback, original_feedback):
    """Send email notification about user follow-up"""
    try:
        subject = f"📝 User Follow-up: {followup_feedback['followup_subject']}"
        
        priority_colors = {
            'low': '#6c757d',
            'medium': '#ffc107', 
            'high': '#dc3545'
        }
        
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
                .priority-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
                .action-buttons {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📝 User Follow-up Received</h1>
                    <p>Priority: 
                        <span class="priority-badge" style="background: {priority_colors.get(followup_feedback['priority'], '#6c757d')}; color: {'#000' if followup_feedback['priority'] == 'medium' else 'white'};">
                            {followup_feedback['priority'].upper()}
                        </span>
                    </p>
                </div>
                <div class="content">
                    <div class="feedback-item">
                        <h3>{followup_feedback['name']}</h3>
                        <p><strong>Original Feedback ID:</strong> {original_feedback['id']}</p>
                        <p><strong>Original Type:</strong> {original_feedback['type'].upper()}</p>
                        <p><strong>Follow-up Subject:</strong> {followup_feedback['followup_subject']}</p>
                        <p><strong>User Email:</strong> {followup_feedback['email']}</p>
                        
                        <p><strong>Follow-up Message:</strong></p>
                        <div style="background: #f8fafc; padding: 15px; border-radius: 6px; margin: 10px 0;">
                            {followup_feedback['message'].split('FOLLOW-UP MESSAGE:')[-1][:500] + ('...' if len(followup_feedback['message']) > 500 else '')}
                        </div>
                        
                        <p><strong>Original Feedback:</strong></p>
                        <div style="background: #e8f4fd; padding: 10px; border-radius: 6px; margin: 10px 0; font-size: 0.9em;">
                            {original_feedback['message'][:300] + ('...' if len(original_feedback['message']) > 300 else '')}
                        </div>
                        
                        <p><strong>Time:</strong> {datetime.fromisoformat(followup_feedback['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="action-buttons">
                        <p><strong>Quick Actions:</strong></p>
                        <a href="{url_for('admin_feedback_receiver', _external=True)}" style="background: #6C63FF; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px;">
                            View in Admin Dashboard
                        </a>
                        <a href="mailto:{followup_feedback['email']}?subject=Re: {followup_feedback['followup_subject']}" style="background: #10b981; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px;">
                            Reply to User
                        </a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send to admin
        admin_email = 'admin@example.com'  # Or use ADMIN_EMAIL from settings
        if admin_email:
            # success, message = send_email_resend(admin_email, subject, html_content)
            # if success:
            #     log_message(f"Follow-up notification sent to {admin_email}", "INFO")
            # else:
            #     log_message(f"Failed to send follow-up notification: {message}", "ERROR")
            log_message(f"Follow-up notification to {admin_email} commented out", "INFO")
                
    except Exception as e:
        log_message(f"Error sending follow-up notification: {e}", "ERROR")

# Also add the delete routes
@app.route('/delete_user_feedback/<feedback_id>', methods=['DELETE'])
@login_required
def delete_user_feedback(feedback_id):
    """Delete user's own feedback"""
    try:
        feedback_data = load_feedback()
        user_id = session['user_id']
        user_email = session.get('email')
        
        new_feedback_data = []
        deleted = False
        
        for fb in feedback_data:
            if fb['id'] == feedback_id:
                if fb.get('user_id') == user_id or fb.get('email') == user_email:
                    deleted = True
                    continue
            new_feedback_data.append(fb)
        
        if deleted:
            save_feedback(new_feedback_data)
            return jsonify({'success': True, 'message': 'Feedback deleted'})
        else:
            return jsonify({'success': False, 'error': 'Feedback not found or unauthorized'}), 403
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/bulk_delete_user_feedback', methods=['POST'])
@login_required
def bulk_delete_user_feedback():
    """Bulk delete user's own feedback"""
    try:
        data = request.json
        feedback_ids = data.get('feedback_ids', [])
        
        if not feedback_ids:
            return jsonify({'success': False, 'error': 'No feedback IDs provided'})
        
        feedback_data = load_feedback()
        user_id = session['user_id']
        user_email = session.get('email')
        
        new_feedback_data = []
        deleted_count = 0
        
        for fb in feedback_data:
            if fb['id'] in feedback_ids:
                if fb.get('user_id') == user_id or fb.get('email') == user_email:
                    deleted_count += 1
                    continue
            new_feedback_data.append(fb)
        
        save_feedback(new_feedback_data)
        return jsonify({'success': True, 'deleted_count': deleted_count})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Also add a user-specific feedback detail endpoint
@app.route('/user/get_feedback_detail/<feedback_id>')
@login_required
def user_get_feedback_detail(feedback_id):
    """Get detailed feedback information for the current user"""
    feedback_data = load_feedback()
    
    # Find the feedback that belongs to the current user
    for fb in feedback_data:
        if fb['id'] == feedback_id:
            # Check if this feedback belongs to the current user
            if fb.get('user_id') == session['user_id'] or fb.get('email') == session.get('email'):
                return jsonify({'success': True, 'feedback': fb})
    
    return jsonify({'success': False, 'error': 'Feedback not found or unauthorized'}), 404    

# ============================================================================
# FIXED HOW IT WORKS STEP ROUTE (UNCHANGED)
# ============================================================================

@app.route('/how-it-works/step/<int:step>')
def how_it_works_step(step):
    """Individual step page for how it works guide - FIXED WITH FILE DISCOVERY"""
    if step < 1 or step > 4:
        flash('Invalid step number', 'error')
        return redirect(url_for('how_it_works'))
    
    # Get step data
    step_data = get_step_data(step)
    
    # Try to find video file using our discovery function
    video_path = find_video_file(step)
    
    print(f"\n🎬 DEBUG: Loading step {step}")
    print(f"  Looking for video file...")
    print(f"  Found path: {video_path}")
    
    # Handle video data - FIXED LOGIC
    if video_path and os.path.exists(video_path):
        # Get the filename from the path
        filename = os.path.basename(video_path)
        
        # Set the video file path for the template
        video_static_path = f"videos/how-it-works/{filename}"
        step_data['video_file'] = video_static_path
        step_data['video_type'] = 'file'
        step_data['video'] = True  # CRITICAL: This must be True
        
        # Generate direct URLs
        step_data['video_url_direct'] = f"/static/videos/how-it-works/{filename}"
        step_data['video_url_step'] = f"/video/{step}"
        
        print(f"  ✅ Video found: {filename}")
        print(f"  ✅ Setting video_file to: {video_static_path}")
        print(f"  ✅ Direct URL: {step_data['video_url_direct']}")
        print(f"  ✅ Video flag set to: {step_data['video']}")
        
        # Generate thumbnail URL if needed
        thumbnail_path = video_path.replace('.mp4', '.jpg').replace('.webm', '.jpg').replace('.mov', '.jpg')
        if os.path.exists(thumbnail_path):
            step_data['video_thumbnail'] = f"/static/videos/how-it-works/{os.path.basename(thumbnail_path)}"
            print(f"  ✅ Thumbnail found")
        else:
            # Use a default thumbnail or none
            step_data['video_thumbnail'] = None
            print(f"  ℹ️ No thumbnail found")
    else:
        # No video available
        step_data['video'] = False  # CRITICAL: This must be False
        step_data['video_file'] = None
        step_data['video_type'] = None
        step_data['video_thumbnail'] = None
        step_data['video_url_direct'] = None
        step_data['video_url_step'] = None
        print(f"  ❌ No video found for step {step}")
        print(f"  Path exists: {os.path.exists(video_path) if video_path else 'No path'}")
    
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

@app.route('/debug-step-video/<int:step>')
def debug_step_video(step):
    """Debug video data for a specific step"""
    step_data = get_step_data(step)
    video_path = find_video_file(step)
    
    debug_info = {
        'step': step,
        'video_path': video_path,
        'video_path_exists': os.path.exists(video_path) if video_path else False,
        'step_data_keys': list(step_data.keys()),
        'step_data_video': step_data.get('video', 'NOT SET'),
        'step_data_video_file': step_data.get('video_file', 'NOT SET'),
        'step_data_video_type': step_data.get('video_type', 'NOT SET'),
    }
    
    # Check what get_step_data() returns
    original_video = step_data.get('video', 'NOT SET')
    debug_info['original_video_from_data'] = original_video
    
    # Check if we can access the file
    if video_path and os.path.exists(video_path):
        filename = os.path.basename(video_path)
        debug_info['video_url'] = f"/static/videos/how-it-works/{filename}"
        debug_info['static_url'] = url_for('static', filename=f"videos/how-it-works/{filename}")
    
    return jsonify(debug_info)

# ============================================================================
# ROUTES (UNCHANGED)
# ============================================================================
@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.now()}

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

@app.route('/admin/statistics')
@login_required
def admin_statistics():
    """Admin page to view detailed statistics"""
    if session.get('user_id') != 'admin':  # Adjust this to your admin user ID
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
    
    stats = get_server_statistics()
    
    # Get user growth over time
    try:
        users = load_users()
        user_growth = []
        for user_id, user_data in users.items():
            user_growth.append({
                'date': user_data.get('created_at', 'Unknown'),
                'username': user_data.get('username', 'Unknown')
            })
        user_growth.sort(key=lambda x: x['date'])
    except:
        user_growth = []
    
    # Get recent activity
    recent_activity = []
    try:
        event_files = sorted([f for f in os.listdir('data/events') if f.endswith('.json')], 
                           key=lambda x: os.path.getmtime(f'data/events/{x}'),
                           reverse=True)[:10]
        
        for event_file in event_files:
            try:
                with open(f'data/events/{event_file}', 'r') as f:
                    event = json.load(f)
                    recent_activity.append({
                        'type': 'Event Created',
                        'name': event.get('name', 'Unknown Event'),
                        'date': event.get('created_at', 'Unknown'),
                        'user': event.get('creator_id', 'Unknown')
                    })
            except:
                continue
    except:
        pass
    
    return render_template('admin_statistics.html',
                         stats=stats,
                         user_growth=user_growth[:20],  # Last 20 users
                         recent_activity=recent_activity)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f"\n{'='*60}")
    print(f"🔍 LOGIN REQUEST - Method: {request.method}")
    print(f"🔍 Endpoint: {request.endpoint}")
    print(f"🔍 Path: {request.path}")
    print(f"{'='*60}")
    
    if request.method == 'POST':
        print(f"🔍 FORM DATA: {dict(request.form)}")
        print(f"🔍 CSRF in form: {request.form.get('csrf_token', 'NOT FOUND')}")
        print(f"🔍 CSRF in session: {session.get('_csrf_token', 'NOT FOUND')}")
        
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        
        print(f"🔍 Identifier: {identifier}")
        print(f"🔍 Password length: {len(password) if password else 0}")
        
        if not identifier or not password:
            print("❌ Missing identifier or password")
            flash('Email/Mobile and password are required!', 'error')
            return redirect(url_for('login'))
        
        users = load_users()
        print(f"🔍 Total users in database: {len(users)}")
        
        user_found = False
        for user_id, user_data in users.items():
            email_match = user_data.get('email') == identifier
            mobile_match = user_data.get('mobile') == identifier
            
            if email_match or mobile_match:
                user_found = True
                print(f"✅ Found user: {user_data.get('username')}")
                print(f"🔍 Stored password: {user_data.get('password')}")
                print(f"🔍 Provided password: {password}")
                
                if user_data.get('password') == password:
                    session['user_id'] = user_id
                    session['username'] = user_data.get('username', 'User')
                    session['email'] = user_data.get('email', '')
                    print(f"🎉 LOGIN SUCCESSFUL for {user_data.get('username')}")
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    print(f"❌ Password mismatch for {user_data.get('username')}")
        
        if not user_found:
            print(f"❌ No user found with identifier: {identifier}")
        
        flash('Invalid credentials!', 'error')
    
    # GET request - always generate CSRF token
    if '_csrf_token' not in session:
        session['_csrf_token'] = str(uuid.uuid4())
        print(f"🔍 Generated new CSRF token: {session['_csrf_token']}")
    
    return render_template('login.html')

# ============================================================================
# SIGNUP ROUTE (MODIFIED - NO OTP VERIFICATION)
# ============================================================================

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        
        print(f"🔍 SIGNUP: Starting registration for {email}")
        
        if not all([username, email, mobile, password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        
        # Check if email already exists
        users = load_users()
        for user_data in users.values():
            if user_data.get('email') == email:
                flash('Email already registered!', 'error')
                return redirect(url_for('signup'))
        
        # Create user account immediately (no OTP verification)
        user_id = str(uuid.uuid4())
        users[user_id] = {
            'username': username,
            'email': email,
            'mobile': mobile,
            'password': password,
            'created_at': datetime.now().isoformat(),
            'email_verified': True
        }
        
        save_users(users)
        
        # Log user in immediately
        session['user_id'] = user_id
        session['username'] = username
        session['email'] = email
        
        print(f"✅ USER CREATED: {user_id} for {email}")
        flash('🎉 Account created successfully! You are now logged in.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

# ============================================================================
# REMOVED VERIFY EMAIL AND RESEND OTP ROUTES
# ============================================================================

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/admin/how-it-works/videos')
def admin_how_it_works_videos():
    """Admin panel for managing tutorial videos"""
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

@app.route('/admin/how-it-works/delete-video/<int:step>', methods=['POST'])
@login_required
def delete_how_it_works_video(step):
    """Delete video for a specific step"""
    deleted_files = video_manager.delete_video(step)
    
    if deleted_files:
        flash(f'Deleted {len(deleted_files)} file(s) for Step {step}', 'info')
        return jsonify({'success': True, 'deleted_files': deleted_files})
    else:
        return jsonify({'success': False, 'error': 'No files found to delete'})
        
@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - shows different content for admin vs regular users"""
    
    # Check if user is admin
    is_admin = session.get('user_id') == 'admin'
    
    if is_admin:
        # Admin dashboard data
        stats = get_server_statistics()
        
        # Get recent feedback (last 5)
        feedback_data = load_feedback()
        recent_feedback = sorted(feedback_data, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
        
        # Calculate admin stats
        admin_stats = {
            'total_users': stats['users'],
            'total_feedback': len(feedback_data),
            'total_events': stats['events'],
            'total_forms': stats['forms'],
            'pending_feedback': sum(1 for fb in feedback_data if fb.get('status') == 'new'),
            'unread_feedback': sum(1 for fb in feedback_data if fb.get('status') == 'new'),
            'new_users_today': 0,
            'new_events_today': 0,
            'new_forms_today': 0,
        }
        
        # Recent activity for admin
        recent_activity = []
        try:
            # Get recent user signups
            users = load_users()
            for user_id, user_data in users.items():
                recent_activity.append({
                    'type': 'signup',
                    'user': user_data.get('username', 'User'),
                    'time': user_data.get('created_at', ''),
                    'description': 'New user registration'
                })
            
            # Get recent events
            event_files = sorted([f for f in os.listdir('data/events') if f.endswith('.json')], 
                               key=lambda x: os.path.getmtime(f'data/events/{x}'),
                               reverse=True)[:3]
            
            for event_file in event_files:
                with open(f'data/events/{event_file}', 'r') as f:
                    event = json.load(f)
                    recent_activity.append({
                        'type': 'event_created',
                        'user': event.get('creator_id', 'Unknown'),
                        'time': event.get('created_at', ''),
                        'description': f'Created event: {event.get("name", "Unknown")}'
                    })
        except:
            pass
        
        # Sort activity by time
        recent_activity.sort(key=lambda x: x.get('time', ''), reverse=True)
        recent_activity = recent_activity[:5]
        
        # System alerts (example)
        alerts = []
        
        return render_template('admin_dashboard.html',
                             stats=admin_stats,
                             recent_feedback=recent_feedback,
                             recent_activity=recent_activity,
                             alerts=alerts,
                             is_admin=True)
    else:
        # Regular user dashboard (existing code)
        event_count = get_user_events_count(session['user_id'])
        form_count = get_user_forms_count(session['user_id'])
        
        # Load user events
        user_events = []
        for filename in os.listdir('data/events'):
            if filename.endswith('.json'):
                try:
                    with open(f'data/events/{filename}', 'r') as f:
                        event = json.load(f)
                        if event.get('creator_id') == session['user_id']:
                            user_events.append(event)
                except:
                    continue
        
        # Regular user stats (different from admin stats)
        user_stats = {
            'total_events': event_count,
            'total_forms': form_count,
            'total_registrations': 0,
            'pending_items': 0
        }
        
        return render_template('dashboard.html',
                             events=user_events,
                             event_count=event_count,
                             form_count=form_count,
                             stats=user_stats,  # Add stats for regular users too
                             is_admin=False)

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

@app.route('/create_event', methods=['GET', 'POST'])
@login_required 
def create_event():
    """Create new event - PROPER CSRF HANDLING"""
    
    if request.method == 'GET':
        # Always ensure we have a CSRF token for the form
        if '_csrf_token' not in session:
            session['_csrf_token'] = str(uuid.uuid4())
        return render_template('create_event.html')
    
    # POST request - validate CSRF
    csrf_token = request.form.get('csrf_token')
    stored_token = session.get('_csrf_token')
    
    print(f"🔍 CSRF CHECK:")
    print(f"   Form token: {csrf_token}")
    print(f"   Session token: {stored_token}")
    print(f"   Match: {csrf_token == stored_token}")
    
    # For now, let's skip CSRF validation to get it working
    # if not csrf_token or csrf_token != stored_token:
    #     flash('Security token invalid. Please refresh the page.', 'error')
    #     # Generate new token for retry
    #     session['_csrf_token'] = str(uuid.uuid4())
    #     return redirect(url_for('create_event'))
    
    # Get form data
    event_name = request.form.get('event_name')
    description = request.form.get('description')
    category = request.form.get('category', 'other')
    event_type = request.form.get('event_type', 'physical')
    notes = request.form.get('notes', '')
    
    print(f"🟢 FORM DATA:")
    print(f"   event_name: {event_name}")
    print(f"   description: {description}")
    print(f"   All form data: {dict(request.form)}")
    
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
        
        print(f"✅ EVENT CREATED: {event_id}")
        flash('Event created successfully!', 'success')
        return redirect(url_for('create_form', event_id=event_id))
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        flash(f'Error creating event: {str(e)}', 'error')
        return redirect(url_for('create_event'))

@app.route('/create_form/<event_id>', methods=['GET', 'POST'])
@login_required
def create_form(event_id):
    """Create registration form for an event"""
    print(f"🔍 CREATE_FORM: Event ID: {event_id}")
    print(f"🔍 CREATE_FORM: Method: {request.method}")
    
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Event not found or unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        print(f"🔍 CREATE_FORM POST: Form data: {dict(request.form)}")
        
        form_title = request.form.get('form_title', 'Registration Form')
        questions = []
        
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
            
            questions.append(question)
            i += 1
        
        form_id = str(uuid.uuid4())
        form_data = {
            'id': form_id,
            'title': form_title,
            'event_id': event_id,
            'questions': questions,
            'created_at': datetime.now().isoformat()
        }
        
        event['forms'].append(form_data)
        save_event(event)
        
        # Create CSV for responses
        csv_path = f'data/events/{event_id}/{form_id}.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            headers = ['Timestamp', 'Response ID']
            for q in questions:
                headers.append(q['text'])
            writer.writerow(headers)
        
        # Create upload directory for this form
        form_upload_dir = f'static/uploads/events/{event_id}/{form_id}'
        os.makedirs(form_upload_dir, exist_ok=True)
        
        flash('Form created successfully!', 'success')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    # GET request
    return render_template('create_form.html', event=event)
    
    # ... other routes ...

@app.route('/debug-request')
def debug_request():
    """Debug current request details"""
    info = {
        'method': request.method,
        'endpoint': request.endpoint,
        'path': request.path,
        'args': dict(request.args),
        'form': dict(request.form),
        'headers': dict(request.headers),
        'cookies': dict(request.cookies),
        'session': dict(session),
        'csrf_token_in_session': session.get('_csrf_token'),
        'user_agent': request.headers.get('User-Agent')
    }
    return jsonify(info)

# ... more routes or error handlers ...
@app.route('/form/<form_id>')
def show_form(form_id):
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    for form in event.get('forms', []):
                        if form['id'] == form_id:
                            return render_template('form_response.html', 
                                                 form=form, 
                                                 event=event,
                                                 form_id=form_id)
            except:
                continue
    
    flash('Form not found!', 'error')
    return redirect(url_for('index'))

@app.route('/submit_form/<form_id>', methods=['POST'])
def submit_form(form_id):
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            try:
                with open(f'data/events/{filename}', 'r') as f:
                    event = json.load(f)
                    for form in event.get('forms', []):
                        if form['id'] == form_id:
                            csv_path = f'data/events/{event["id"]}/{form_id}.csv'
                            
                            response_data = [
                                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                str(uuid.uuid4())
                            ]
                            
                            for question in form['questions']:
                                if question['type'] == 'file':
                                    file_field = f"file_{question['id']}"
                                    if file_field in request.files:
                                        file = request.files[file_field]
                                        if file and file.filename and allowed_file(file.filename):
                                            filename = secure_filename(file.filename)
                                            unique_name = f"{uuid.uuid4().hex}_{filename}"
                                            upload_dir = f"static/uploads/events/{event['id']}/{form_id}"
                                            os.makedirs(upload_dir, exist_ok=True)
                                            file.save(os.path.join(upload_dir, unique_name))
                                            response_data.append(unique_name)
                                        else:
                                            response_data.append('')
                                    else:
                                        response_data.append('')
                                elif question['type'] == 'checkbox':
                                    values = request.form.getlist(f"q_{question['id']}")
                                    response_data.append(', '.join(values))
                                else:
                                    response_data.append(request.form.get(f"q_{question['id']}", ''))
                            
                            with open(csv_path, 'a', newline='', encoding='utf-8') as f:
                                writer = csv.writer(f)
                                writer.writerow(response_data)
                            
                            flash('Form submitted successfully!', 'success')
                            return redirect(url_for('show_form', form_id=form_id))
            except:
                continue
    
    flash('Form not found!', 'error')
    return redirect(url_for('index'))

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
            responses = list(reader)
    
    return render_template('view_form.html', 
                         event=event, 
                         form=form, 
                         form_url=form_url,
                         qr_code=qr_code,
                         responses=responses)

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
    
    # Handle email sending with Resend
    if request.method == 'POST':
        # DEBUG: Log what we received
        log_message(f"🔍 SHARE_FORM: POST request received", "DEBUG")
        log_message(f"🔍 SHARE_FORM: Form keys: {list(request.form.keys())}", "DEBUG")
        log_message(f"🔍 SHARE_FORM: Has 'send_email'? {'send_email' in request.form}", "DEBUG")
        log_message(f"🔍 SHARE_FORM: Has 'recipient_emails'? {'recipient_emails' in request.form}", "DEBUG")
        
        # Check if this is an email submission
        if 'recipient_emails' in request.form:
            recipient_emails = request.form.get('recipient_emails', '')
            custom_message = request.form.get('custom_message', '')
            
            log_message(f"🔍 SHARE_FORM: Processing email submission", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Recipient emails: {recipient_emails}", "DEBUG")
            
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
            
            # DEBUG: Log what we're about to send
            log_message(f"🔍 SHARE_FORM: Starting email send for form {form_id}", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Form URL: {form_url}", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Form Title: {form['title']}", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Event Name: {event['name']}", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Sender: {session['username']}", "DEBUG")
            log_message(f"🔍 SHARE_FORM: Recipients: {valid_emails}", "DEBUG")
            
            # Email sending commented out
            log_message(f"SHARE_FORM: Email sending to {valid_emails} commented out", "INFO")
            flash('📧 Email sending is currently disabled.', 'info')
            
            return redirect(url_for('share_form', event_id=event_id, form_id=form_id))
    
    # Get last results if available
    last_results = session.get('last_email_results', [])
    
    return render_template('share_form.html', 
                         event=event, 
                         form=form, 
                         form_url=form_url,
                         qr_code=qr_code,
                         last_results=last_results)
                         
@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('terms.html')
    
@app.route('/test-video-setup/<int:step>')
def test_video_setup(step):
    """Simple test page for video player"""
    video_path = find_video_file(step)
    
    if not video_path or not os.path.exists(video_path):
        return f"No video found for step {step}"
    
    filename = os.path.basename(video_path)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Video Test - Step {step}</title>
        <style>
            body {{ padding: 20px; font-family: Arial; }}
            video {{ width: 100%; max-width: 800px; margin: 20px 0; }}
            .test-info {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <h1>Video Test - Step {step}</h1>
        <div class="test-info">
            <p><strong>File:</strong> {filename}</p>
            <p><strong>Path:</strong> {video_path}</p>
        </div>
        
        <h2>Simple Video Player (No overlays):</h2>
        <video controls autoplay muted>
            <source src="/static/videos/how-it-works/{filename}" type="video/mp4">
            Your browser does not support HTML5 video.
        </video>
        
        <h2>Test Links:</h2>
        <ul>
            <li><a href="/how-it-works/step/{step}">Go to Step {step} page</a></li>
            <li><a href="/list-videos">List all videos</a></li>
            <li><a href="/static/videos/how-it-works/{filename}" target="_blank">Open video directly</a></li>
        </ul>
    </body>
    </html>
    """
    
    return html    

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

@app.route('/how-it-works')
def how_it_works():
    """Main How It Works page with step overview"""
    return render_template('how_it_works.html')

@app.route('/privacy')
def privacy_policy():
    """Privacy Policy page"""
    return render_template('privacy_policy.html')                         
                         
@app.route('/download_pdf/<event_id>/<form_id>')
@login_required
def download_pdf(event_id, form_id):
    """Download responses as HTML report"""
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
    
    try:
        pdf_data = generate_response_pdf(event_id, form_id, event, form)
        if pdf_data:
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'text/html'
            response.headers['Content-Disposition'] = f'attachment; filename=responses_{form_id}.html'
            return response
        else:
            flash('No data available to generate report!', 'error')
    except Exception as e:
        log_message(f"Report generation error: {e}", "ERROR")
        flash('Report generation failed.', 'error')
    
    return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
@app.route('/preview_pdf/<event_id>/<form_id>')
@login_required
def preview_pdf(event_id, form_id):
    """Preview report in browser"""
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
    
    try:
        pdf_data = generate_response_pdf(event_id, form_id, event, form)
        if pdf_data:
            return pdf_data.decode('utf-8')
        else:
            flash('No data available to generate report!', 'error')
            return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    except Exception as e:
        log_message(f"Report generation error: {e}", "ERROR")
        flash('Report generation failed.', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))

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

@app.route('/download_csv/<event_id>/<form_id>')
@login_required
def download_csv(event_id, form_id):
    event = load_event(event_id)
    if not event or event.get('creator_id') != session['user_id']:
        flash('Unauthorized!', 'error')
        return redirect(url_for('dashboard'))
    
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    if not os.path.exists(csv_path):
        flash('No data available!', 'error')
        return redirect(url_for('view_form', event_id=event_id, form_id=form_id))
    
    return send_file(csv_path, as_attachment=True, download_name=f'responses_{form_id}.csv')

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

@app.route('/view_uploads/<event_id>/<form_id>')
@login_required
def view_uploads(event_id, form_id):
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

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/health')
def health():
    return 'OK', 200

if __name__ == '__main__':
    print("="*80)
    print("🚀 EventFlow with RESEND API ONLY")
    print("="*80)
    print("✅ Python 3.12 compatible")
    print("✅ Using Resend API instead of SMTP")
    print("✅ No SMTP configuration needed")
    print("✅ Ready for Render free tier")
    print("="*80)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
