# update_app_paths.py
import re

# Read the app.py file
with open('app.py', 'r') as f:
    content = f.read()

print("Original file loaded. Starting updates...")

# First, add the get_data_path function if not present
if 'def get_data_path' not in content:
    # Find where to insert it (after imports)
    insert_point = content.find('load_dotenv()')
    if insert_point != -1:
        insert_point = content.find('\n', insert_point) + 1
        new_function = '''
def get_data_path(subpath=''):
    """Get path for persistent data storage - WORKS ON BOTH LOCAL AND RENDER"""
    base_path = os.environ.get('PERSISTENT_DATA_PATH', 'data')
    full_path = os.path.join(base_path, subpath)
    
    # Create directory if needed
    if '/' in subpath:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
    elif subpath and '.' not in subpath:  # It's a directory
        os.makedirs(full_path, exist_ok=True)
    
    return full_path
'''
        content = content[:insert_point] + new_function + content[insert_point:]
        print("✅ Added get_data_path() function")

# Define replacement patterns (careful not to replace static paths)
patterns = [
    # CRITICAL: User data files
    (r"with open\('data/users\.json'", r"with open(get_data_path('users.json')"),
    (r'with open\("data/users\.json"', r'with open(get_data_path("users.json")'),
    
    # Event JSON files (but not static files)
    (r"with open\('data/events/([^']+\.json)'", r"with open(get_data_path('events/\1')"),
    (r'with open\("data/events/([^"]+\.json)"', r'with open(get_data_path("events/\1")'),
    
    # Event directory paths for files
    (r"'data/events/([^']+)'\)", r"get_data_path('events/\1')"),
    (r'"data/events/([^"]+)"\)', r'get_data_path("events/\1")'),
    
    # Reports directory
    (r"'data/reports/([^']+)'", r"get_data_path('reports/\1')"),
    (r'"data/reports/([^"]+)"', r'get_data_path("reports/\1")"),
    
    # Email status
    (r"'data/email_status/([^']+)'", r"get_data_path('email_status/\1')"),
    (r'"data/email_status/([^"]+)"', r'get_data_path("email_status/\1")'),
    
    # Feedback files
    (r"'data/feedback\.json'", r"get_data_path('feedback.json')"),
    (r'"data/feedback\.json"', r'get_data_path("feedback.json")'),
    
    # OTP store
    (r"'data/otp_store\.json'", r"get_data_path('otp_store.json')"),
    (r'"data/otp_store\.json"', r'get_data_path("otp_store.json")"),
    
    # Directory creation
    (r"os\.makedirs\('data/([^']+)'", r"os.makedirs(get_data_path('\1')"),
    (r'os\.makedirs\("data/([^"]+)"', r'os.makedirs(get_data_path("\1")'),
    
    # Directory listing
    (r"os\.listdir\('data/([^']+)'\)", r"os.listdir(get_data_path('\1'))"),
    (r'os\.listdir\("data/([^"]+)"\)', r'os.listdir(get_data_path("\1"))'),
    
    # Path exists
    (r"os\.path\.exists\('data/([^']+)'\)", r"os.path.exists(get_data_path('\1'))"),
    (r'os\.path\.exists\("data/([^"]+)"\)', r'os.path.exists(get_data_path("\1"))"),
]

# Apply replacements
updated_content = content
for pattern, replacement in patterns:
    updated_content = re.sub(pattern, replacement, updated_content)

# Write back
with open('app.py', 'w') as f:
    f.write(updated_content)

print("✅ File paths updated in app.py")
print("\nIMPORTANT: Check these static paths were NOT changed:")
print("  - 'static/uploads/'")
print("  - 'static/videos/'")
print("  - 'static/qr_codes/'")
print("  - 'logs/' (log files)")
