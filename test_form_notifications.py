import json
import os
from datetime import datetime, timedelta

print("🧪 Testing Form Notification System")
print("=" * 60)

# Test 1: Check if any forms have notify_on_end = True
forms_with_notify = []
for filename in os.listdir('data/events'):
    if filename.endswith('.json'):
        with open(f'data/events/{filename}', 'r', encoding='utf-8') as f:
            event = json.load(f)
        
        for form in event.get('forms', []):
            schedule = form.get('schedule', {})
            if schedule.get('notify_on_end') == True:
                forms_with_notify.append({
                    'event': event['name'],
                    'form': form['title'],
                    'notify_on_end': schedule.get('notify_on_end'),
                    'end_datetime': schedule.get('end_datetime'),
                    'notification_sent': schedule.get('notification_sent', False)
                })

print(f"📋 Found {len(forms_with_notify)} forms with notify_on_end = True:")
for form in forms_with_notify:
    print(f"  • {form['event']} - {form['form']}")
    print(f"    End: {form['end_datetime']}")
    print(f"    Already sent: {form['notification_sent']}")
    print()

# Test 2: Check if forms have ended
now = datetime.now()
for form in forms_with_notify:
    if form['end_datetime']:
        try:
            end_dt = datetime.fromisoformat(
                form['end_datetime'].replace('T', ' ') if 'T' in form['end_datetime'] else form['end_datetime']
            )
            if now >= end_dt and not form['notification_sent']:
                print(f"⚠️  {form['form']} has ended but notification not sent!")
            elif now >= end_dt and form['notification_sent']:
                print(f"✅ {form['form']} has ended and notification was sent")
            else:
                print(f"⏳ {form['form']} ends in {end_dt - now}")
        except Exception as e:
            print(f"❌ Error parsing datetime for {form['form']}: {e}")

print("\n✅ Test complete. Check logs/email.log for email sending details.")
