import json
import os
from datetime import datetime, timedelta

class BotProtection:
    def __init__(self, storage_dir='data/ip_tracking'):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
    
    def check_and_block(self, form_id, ip_address):
        """Check if IP should be blocked, return (allow, reason)"""
        # Clean IP for filename
        safe_ip = ip_address.replace('.', '_').replace(':', '_')
        ip_file = os.path.join(self.storage_dir, f"{form_id}_{safe_ip}.json")
        
        now = datetime.now()
        
        # Load existing data or create new
        if os.path.exists(ip_file):
            with open(ip_file, 'r') as f:
                data = json.load(f)
            
            # Convert string times to datetime
            last_time = datetime.fromisoformat(data['last_submission'])
            first_time = datetime.fromisoformat(data['first_submission'])
            
            # Check time windows
            time_since_last = now - last_time
            
            # Rule 1: Too fast submissions (less than 5 seconds)
            if time_since_last.total_seconds() < 5:
                data['fast_submissions'] = data.get('fast_submissions', 0) + 1
                if data['fast_submissions'] >= 3:
                    data['blocked_until'] = (now + timedelta(hours=1)).isoformat()
                    self._save_data(ip_file, data)
                    return False, "Blocked for 1 hour (too many fast submissions)"
            
            # Rule 2: Too many submissions in 1 minute
            if time_since_last.total_seconds() < 60:
                data['minute_count'] = data.get('minute_count', 0) + 1
                if data['minute_count'] >= 10:
                    data['blocked_until'] = (now + timedelta(hours=2)).isoformat()
                    self._save_data(ip_file, data)
                    return False, "Blocked for 2 hours (too many submissions per minute)"
            
            # Rule 3: Check if currently blocked
            if 'blocked_until' in data:
                blocked_until = datetime.fromisoformat(data['blocked_until'])
                if now < blocked_until:
                    time_left = blocked_until - now
                    hours = int(time_left.total_seconds() // 3600)
                    minutes = int((time_left.total_seconds() % 3600) // 60)
                    return False, f"Blocked for {hours}h {minutes}m"
                else:
                    # Unblock if time has passed
                    data.pop('blocked_until', None)
            
            # Reset minute count if more than 1 minute passed
            if time_since_last.total_seconds() >= 60:
                data['minute_count'] = 1
            else:
                data['minute_count'] = data.get('minute_count', 0) + 1
            
            # Update data
            data['last_submission'] = now.isoformat()
            data['total_submissions'] = data.get('total_submissions', 0) + 1
            
        else:
            # First submission from this IP
            data = {
                'ip': ip_address,
                'first_submission': now.isoformat(),
                'last_submission': now.isoformat(),
                'total_submissions': 1,
                'minute_count': 1,
                'fast_submissions': 0
            }
        
        self._save_data(ip_file, data)
        return True, "OK"
    
    def _save_data(self, filename, data):
        """Save IP data to file"""
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

# Initialize bot protection
bot_protector = BotProtection()
