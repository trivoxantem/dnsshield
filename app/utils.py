import dns.resolver
from datetime import datetime

from . import models


def fetch_dns_records(domain_name):
    """Fetch basic DNS records using dnspython. Returns list of (type, value)."""
    results = []
    for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain_name, rtype, lifetime=5)
            for r in answers:
                results.append((rtype, r.to_text()))
        except Exception:
            continue
    return results


def record_changes_for_domain(domain_obj):
    """Compare fetched records with stored records and create DNSChangeLog entries."""
    current = {(r.record_type, r.value) for r in domain_obj.records.all()}
    fetched = set(fetch_dns_records(domain_obj.name))

    added = fetched - current
    removed = current - fetched

    for rtype, value in added:
        models.DNSChangeLog.objects.create(domain=domain_obj, record_type=rtype, new_value=value, change_type='added', detected_at=datetime.utcnow())

    for rtype, value in removed:
        models.DNSChangeLog.objects.create(domain=domain_obj, record_type=rtype, old_value=value, change_type='removed', detected_at=datetime.utcnow())

    # Update last_checked
    domain_obj.last_checked = datetime.utcnow()
    domain_obj.save(update_fields=['last_checked'])
