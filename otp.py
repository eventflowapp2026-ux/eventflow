"""
Persistent OTP Storage with debug logging
"""
import json
import random
import time
import os
from datetime import datetime

OTP_FILE = 'data/otp_store.json'
os.makedirs('data', exist_ok=True)

def _load_otp_store():
    """Load OTP store from file"""
    try:
        if os.path.exists(OTP_FILE):
            with open(OTP_FILE, 'r') as f:
                store = json.load(f)
                print(f"📂 OTP store loaded: {len(store)} OTP(s)")
                return store
    except Exception as e:
        print(f"❌ Error loading OTP store: {e}")
    return {}

def _save_otp_store(store):
    """Save OTP store to file"""
    try:
        with open(OTP_FILE, 'w') as f:
            json.dump(store, f, indent=2)
        print(f"💾 OTP store saved: {len(store)} OTP(s)")
        return True
    except Exception as e:
        print(f"❌ Error saving OTP store: {e}")
        return False

def generate_and_store_otp(email: str) -> str:
    """Generate OTP and store it persistently"""
    if not email or '@' not in email:
        print(f"❌ Invalid email for OTP: {email}")
        return None
    
    # Load existing store
    store = _load_otp_store()
    
    # Clean up expired first
    current_time = time.time()
    expired = [e for e, data in store.items() if data.get('expiry', 0) < current_time]
    for e in expired:
        del store[e]
    
    if expired:
        print(f"🧹 Cleaned {len(expired)} expired OTP(s)")
    
    # Generate OTP
    otp = str(random.randint(100000, 999999))
    
    # Store with metadata
    store[email] = {
        'otp': otp,
        'expiry': current_time + 300,  # 5 minutes
        'created_at': current_time,
        'created_date': datetime.now().isoformat(),
        'attempts': 0
    }
    
    # Save persistently
    if _save_otp_store(store):
        print(f"✅ OTP {otp} stored for {email}")
        print(f"   Expires at: {time.ctime(store[email]['expiry'])}")
        return otp
    else:
        print(f"❌ Failed to save OTP for {email}")
        return None

def verify_otp(email: str, user_input: str) -> tuple[bool, str]:
    """Verify OTP from persistent storage"""
    print(f"🔍 OTP VERIFY: Checking {email} with input '{user_input}'")
    
    if not email:
        print("❌ OTP VERIFY: No email provided")
        return False, "Email required"
    
    if not user_input or len(user_input) != 6:
        print("❌ OTP VERIFY: Invalid OTP length/format")
        return False, "Please enter a valid 6-digit code"
    
    # Load store
    store = _load_otp_store()
    
    print(f"🔍 OTP VERIFY: Store has emails: {list(store.keys())}")
    
    # Check if OTP exists
    if email not in store:
        print(f"❌ OTP VERIFY: No OTP found for {email}")
        return False, "No OTP found for this email. Please request a new one."
    
    otp_data = store[email]
    current_time = time.time()
    
    print(f"🔍 OTP VERIFY: Stored OTP: {otp_data['otp']}")
    print(f"🔍 OTP VERIFY: Expires at: {time.ctime(otp_data['expiry'])}")
    print(f"🔍 OTP VERIFY: Current time: {time.ctime(current_time)}")
    
    # Check expiry
    if current_time > otp_data['expiry']:
        print(f"❌ OTP VERIFY: OTP expired for {email}")
        del store[email]
        _save_otp_store(store)
        return False, "OTP has expired. Please request a new one."
    
    # Check match
    if user_input.strip() != otp_data['otp'].strip():
        print(f"❌ OTP VERIFY: Mismatch. Input: '{user_input}', Stored: '{otp_data['otp']}'")
        otp_data['attempts'] = otp_data.get('attempts', 0) + 1
        store[email] = otp_data
        _save_otp_store(store)
        
        if otp_data['attempts'] >= 3:
            del store[email]
            _save_otp_store(store)
            return False, "Too many attempts. OTP has been invalidated. Request a new one."
        
        return False, "Invalid OTP. Please try again."
    
    # SUCCESS - Remove OTP after verification
    print(f"✅ OTP VERIFY: Success for {email}")
    del store[email]
    _save_otp_store(store)
    return True, "OTP verified successfully"
