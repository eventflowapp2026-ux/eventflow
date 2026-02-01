# otp.py - FINAL WORKING VERSION
import json
import os
import time
import random

OTP_FILE = 'data/otp_store.json'

def _ensure_directory():
    """Ensure data directory exists"""
    os.makedirs('data', exist_ok=True)

def _load_otp_store():
    """Load OTP store from file - SIMPLE AND RELIABLE"""
    _ensure_directory()
    
    if not os.path.exists(OTP_FILE):
        return {}
    
    try:
        with open(OTP_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except:
        return {}

def _save_otp_store(data):
    """Save OTP store to file - SIMPLE AND RELIABLE"""
    _ensure_directory()
    
    try:
        # Write atomically
        temp_file = OTP_FILE + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=4)
        
        # Replace original
        if os.path.exists(OTP_FILE):
            os.remove(OTP_FILE)
        os.rename(temp_file, OTP_FILE)
        return True
    except Exception as e:
        print(f"❌ ERROR saving OTP: {e}")
        return False

def generate_and_store_otp(email):
    """Generate and store OTP - ULTRA SIMPLE"""
    print(f"\n🔧 OTP: Generating for {email}")
    
    # Generate OTP
    otp = str(random.randint(100000, 999999))
    print(f"🔢 OTP: Generated {otp}")
    
    # Load current store
    store = _load_otp_store()
    print(f"📊 OTP: Store before has {len(store)} entries")
    
    # Add new entry
    store[email] = {
        'otp': otp,
        'timestamp': time.time(),
        'attempts': 0
    }
    
    # Save
    if _save_otp_store(store):
        # Verify it was saved
        verify_store = _load_otp_store()
        if email in verify_store and verify_store[email]['otp'] == otp:
            print(f"✅ OTP: Saved successfully")
            print(f"📊 OTP: Store after has {len(verify_store)} entries")
            return otp
        else:
            print(f"❌ OTP: Save verification FAILED")
            return None
    else:
        print(f"❌ OTP: Save function failed")
        return None

def verify_otp(email, user_otp):
    """Verify OTP - ULTRA SIMPLE"""
    print(f"\n🔍 OTP: Verifying for {email}")
    print(f"🔢 OTP: User input {user_otp}")
    
    store = _load_otp_store()
    print(f"📊 OTP: Store has {len(store)} entries")
    print(f"📊 OTP: Keys: {list(store.keys())}")
    
    if email not in store:
        print(f"❌ OTP: Email not found")
        return False, "No OTP found for this email"
    
    data = store[email]
    stored_otp = data.get('otp')
    
    print(f"📊 OTP: Stored OTP: {stored_otp}")
    
    # Check expiration (5 minutes)
    if time.time() - data.get('timestamp', 0) > 300:
        print(f"❌ OTP: Expired")
        del store[email]
        _save_otp_store(store)
        return False, "OTP expired"
    
    # Check match
    if stored_otp == user_otp:
        print(f"✅ OTP: Matched")
        del store[email]
        _save_otp_store(store)
        return True, "OTP verified"
    else:
        print(f"❌ OTP: Mismatch")
        return False, "Invalid OTP"
