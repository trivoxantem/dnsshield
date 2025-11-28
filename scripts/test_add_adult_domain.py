import os
import sys
# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE','dnsshield.settings')
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
# Force login to avoid password issues
c.force_login(user)
print('Forced login for test user')

# Post JSON
resp = c.post('/api/adult-domain/add/', data='{"url":"1xbet.ng","category":"illegal_content"}', content_type='application/json')
print('Status code:', resp.status_code)
print('Response:', resp.content.decode())

# See if domain created
from app.models import AdultContentDomain
print('Current adult domains count:', AdultContentDomain.objects.count())
print('Last entry:', list(AdultContentDomain.objects.all().values_list('domain','category'))[-5:])
