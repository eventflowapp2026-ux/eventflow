import json
import os
import smtplib
from email.message import EmailMessage
from datetime import datetime
from dotenv import load_dotenv

# ============================
# LOAD ENV
# ============================
load_dotenv()

SMTP_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("MAIL_PORT", 587))
EMAIL_ADDRESS = os.getenv("MAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", EMAIL_ADDRESS)
USERS_FILE = "data/users.json"
EMAIL_BODY_FILE = "email_body.txt"  # <-- new

if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    print("❌ .env missing MAIL_USERNAME or MAIL_PASSWORD")
    exit(1)

# ============================
# LOAD VERIFIED USERS
# ============================
if not os.path.exists(USERS_FILE):
    print("❌ users.json not found")
    exit(1)

with open(USERS_FILE, "r") as f:
    try:
        users = json.load(f)
    except json.JSONDecodeError:
        print("❌ users.json is invalid")
        exit(1)

verified_users = [
    {"id": uid, "email": u["email"], "name": u.get("name", "User")}
    for uid, u in users.items()
    if u.get("email") and u.get("email_verified")
]

if not verified_users:
    print("❌ No verified users found")
    exit(1)

print(f"📬 Found {len(verified_users)} verified user(s).")

# ============================
# LOAD EMAIL SUBJECT AND BODY
# ============================
subject = input("Enter the email subject: ").strip()

if not os.path.exists(EMAIL_BODY_FILE):
    print(f"❌ {EMAIL_BODY_FILE} not found. Create a text file with your email content.")
    exit(1)

with open(EMAIL_BODY_FILE, "r") as f:
    custom_text = f.read().strip()

# ============================
# PROMPT FOR LINKS
# ============================
links_input = input("\nEnter website URLs (separate multiple links with commas): ").strip()
links = [link.strip() for link in links_input.split(",") if link.strip()]

# ============================
# HELPER TO BUILD BUTTONS
# ============================
def build_link_buttons(links):
    buttons_html = ""
    for link in links:
        buttons_html += f'<a href="{link}" class="link-button">{link}</a> '
    return buttons_html

# ============================
# HELPER TO SEND HTML EMAIL
# ============================
def send_email_html(to_email, subject, html_content):
    try:
        msg = EmailMessage()
        msg["From"] = f"EventFlow <{DEFAULT_SENDER}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S")
        msg.set_content("Please use an HTML compatible email client to view this message.")
        msg.add_alternative(html_content, subtype='html')

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        return True, "Sent"
    except Exception as e:
        return False, str(e)

# ============================
# PREVIEW EMAILS
# ============================
print("\n=== EMAIL PREVIEW ===")
for user in verified_users:
    print(f"\nFrom: EventFlow <{DEFAULT_SENDER}>")
    print(f"To: {user['email']}")
    print(f"Subject: {subject}")
    print("Body preview:")
    print(custom_text)
    if links:
        print("Links:")
        for link in links:
            print(" -", link)
    print("-" * 40)

# ============================
# CONFIRM BEFORE SENDING
# ============================
confirm = input("\nSend these emails? (yes/no): ").strip().lower()
if confirm != "yes":
    print("❌ Cancelled. No emails were sent.")
    exit(0)

# ============================
# SEND EMAILS
# ============================
for user in verified_users:
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: auto; background: #f8fafc; padding: 30px; border-radius: 10px; }}
            .header {{ background: #4361ee; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
            .footer {{ margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }}
            .link-button {{ display: inline-block; padding: 10px 20px; background: #4361ee; color: white; border-radius: 5px; text-decoration: none; margin: 5px 5px 0 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📢 EventFlow Notification</h1>
            </div>
            <div style="padding: 30px;">
                <p>Hello {user['name']},</p>
                <p>{custom_text.replace('\n','<br>')}</p>
                <div style="margin-top:20px;">
                    {build_link_buttons(links)}
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} EventFlow. This is an automated email, please do not reply.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    success, message = send_email_html(user["email"], subject, html_content)
    if success:
        print(f"✅ Email sent to {user['email']}")
    else:
        print(f"❌ Failed to send email to {user['email']}: {message}")

print("\n🎉 All emails processed.")

