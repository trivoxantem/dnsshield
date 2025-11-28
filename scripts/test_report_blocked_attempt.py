import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dnsshield.settings')
django.setup()

from django.test import Client
from django.contrib.auth import get_user_model
User = get_user_model()

username = 'testuser'
password = 'TestPass123!'
email = 'testuser@example.com'

user, created = User.objects.get_or_create(username=username, defaults={'email': email})
if created:
    user.set_password(password)
    user.save()
    print('Created test user')
else:
    print('Test user exists')

c = Client()
# Force login
c.force_login(user)
print('Forced login for test user')

# Post blocked attempt report
import json
payload = json.dumps({
    'url': 'https://xnxx.com/some-page',
    'reason': 'Blocked by Chrome extension',
    'category': 'adult_content'
})
resp = c.post('/api/extension/report-blocked-attempt/', data=payload, content_type='application/json')
print('POST /api/extension/report-blocked-attempt/ status:', resp.status_code)
print('Response:', resp.content.decode())

# Fetch alerts for user
resp2 = c.get('/api/alerts/', follow=True)
print('\nGET /api/alerts/ status:', resp2.status_code)
try:
    print('Alerts JSON:', resp2.json())
except Exception:
    print('Raw content:', resp2.content.decode())

# Show whether a matching alert exists
alerts = []
try:
    alerts = resp2.json().get('alerts', [])
except Exception:
    pass

found = False
for a in alerts:
    if a.get('url') and 'xnxx.com' in a.get('url'):
        print('Found alert for xnxx:', a)
        found = True

if not found:
    print('No alert for xnxx found in /api/alerts/ response')
