import os
import sys
import django

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dnsshield.settings')
django.setup()

from django.test import Client

c = Client()
logged_in = c.login(username='testuser', password='testpass')
print('Logged in:', logged_in)
resp = c.get('/api/alerts/')
print('Status code:', resp.status_code)
print('Response:', resp.content.decode())
html_resp = c.get('/alerts/')
print('\nAlerts page HTML snippet:')
content = html_resp.content.decode()
print(content[:1200])
print('\nContains alert text?', 'Suspicious ad reported by browser extension' in content)
