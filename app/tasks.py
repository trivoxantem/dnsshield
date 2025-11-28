from datetime import datetime
from django.core.management.base import BaseCommand

from . import models, utils


class Command(BaseCommand):
    help = 'Scan all domains and detect DNS changes (simple management command)'

    def handle(self, *args, **options):
        domains = models.Domain.objects.all()
        for d in domains:
            try:
                utils.record_changes_for_domain(d)
                self.stdout.write(self.style.SUCCESS(f'Checked {d.name}'))
            except Exception as e:
                self.stderr.write(f'Failed {d.name}: {e}')
