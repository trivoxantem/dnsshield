#!/usr/bin/env python
"""Test script to verify domain addition via Django admin/management."""

import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dnsshield.settings')
django.setup()

from django.contrib.auth import get_user_model
from app.models import Domain

User = get_user_model()

# Get or create a test user
test_user, created = User.objects.get_or_create(
    username='testuser',
    defaults={'email': 'testuser@example.com'}
)
if created:
    test_user.set_password('testpass123')
    test_user.save()
    print(f'✓ Created test user: {test_user.username}')
else:
    print(f'✓ Using existing test user: {test_user.username}')

# Try to add a domain
test_domain_name = 'testdomain.ng'
print(f'\n[TEST] Attempting to create domain: {test_domain_name}')

try:
    # Check if domain already exists
    existing = Domain.objects.filter(name=test_domain_name).first()
    if existing:
        print(f'✗ Domain already exists: {existing.id} - owner: {existing.owner.username}')
        if existing.owner == test_user:
            print(f'  This user owns the domain.')
        else:
            print(f'  Another user owns the domain.')
            # Delete it and recreate
            existing.delete()
            print(f'  Deleted the existing domain.')
    
    # Create the domain
    print(f'Creating domain...')
    domain = Domain.objects.create(
        name=test_domain_name,
        owner=test_user
    )
    print(f'✓ Domain created successfully!')
    print(f'  ID: {domain.id}')
    print(f'  Name: {domain.name}')
    print(f'  Owner: {domain.owner.username}')
    print(f'  Created: {domain.registered_on}')
    
    # Verify it's in the database
    verify = Domain.objects.get(pk=domain.id)
    print(f'✓ Verified domain in database: {verify.name}')
    
    # Check user's domains
    user_domains = Domain.objects.filter(owner=test_user)
    print(f'\n✓ User {test_user.username} has {user_domains.count()} domain(s):')
    for d in user_domains:
        print(f'  - {d.name} (ID: {d.id})')
    
except Exception as e:
    print(f'✗ Error: {type(e).__name__}: {str(e)}')
    import traceback
    traceback.print_exc()

print('\n[DONE]')
