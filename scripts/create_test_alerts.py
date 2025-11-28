import os
import sys
import django

# Ensure project root is on sys.path (so `dnsshield` package is importable)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Ensure DJANGO_SETTINGS_MODULE points to your project settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dnsshield.settings')
django.setup()

from django.contrib.auth import get_user_model
from app import models

User = get_user_model()

user, created = User.objects.get_or_create(username='testuser')
if created:
    user.set_password('testpass')
    user.email = 'test@example.com'
    user.save()
    print('Created user testuser')
else:
    print('User testuser already exists')

# Create domain
domain, dcreated = models.Domain.objects.get_or_create(name='example.ng', owner=user, defaults={'is_active': True})
if dcreated:
    print('Created domain example.ng')
else:
    print('Domain example.ng already exists')

# Create threat alert
alert = models.ThreatAlert.objects.create(
    domain=domain,
    url='https://ads-malicious.com/banner.js',
    reason='Suspicious ad reported by browser extension',
    severity='medium',
    is_resolved=False
)
print('Created ThreatAlert id=', alert.id)

# Create blocked URL
blocked = models.BlockedURL.objects.create(
    url='https://ads-malicious.com/banner.js',
    source='extension',
    domain=domain
)
print('Created BlockedURL id=', blocked.id)

# Print counts
print('Counts:')
print(' ThreatAlerts:', models.ThreatAlert.objects.count())
print(' BlockedURLs:', models.BlockedURL.objects.count())
print(' Domains:', models.Domain.objects.count())
