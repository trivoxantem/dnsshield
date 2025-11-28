#!/usr/bin/env python
"""Fix the adult content blocklist database"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dnsshield.settings')
django.setup()

from app.models import AdultContentDomain

# Delete incorrect entries
AdultContentDomain.objects.all().delete()

# Add correct entries (domain ONLY, no protocol or path)
domains = [
    ('www.youporn.com', 'pornography', 'Pornographic video site'),
    ('pornhub.com', 'pornography', 'Pornographic video site'),
    ('xvideos.com', 'pornography', 'Pornographic video site'),
    ('xnxx.com', 'pornography', 'Pornographic video site'),
    ('redtube.com', 'pornography', 'Pornographic video site'),
]

for domain, category, reason in domains:
    AdultContentDomain.objects.create(
        domain=domain,
        category=category,
        reason=reason,
        is_active=True
    )
    print(f"✅ Added: {domain} ({category})")

print(f"\n✅ Database cleaned and populated with {len(domains)} test domains")
print("\nCurrent blocklist:")
for d in AdultContentDomain.objects.all():
    print(f"  - {d.domain} ({d.category})")
