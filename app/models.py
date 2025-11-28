from django.conf import settings
from django.db import models
from django.utils import timezone


class Domain(models.Model):
	name = models.CharField(max_length=253, unique=True)
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='domains')
	is_active = models.BooleanField(default=True)
	registered_on = models.DateTimeField(default=timezone.now)
	last_checked = models.DateTimeField(null=True, blank=True)
	notes = models.TextField(blank=True)

	class Meta:
		ordering = ['name']

	def __str__(self):
		return self.name


class DNSRecord(models.Model):
	RECORD_TYPES = [
		('A', 'A'),
		('AAAA', 'AAAA'),
		('CNAME', 'CNAME'),
		('MX', 'MX'),
		('TXT', 'TXT'),
		('NS', 'NS'),
	]

	domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='records')
	record_type = models.CharField(max_length=10, choices=RECORD_TYPES)
	name = models.CharField(max_length=253, blank=True)
	value = models.TextField()
	ttl = models.IntegerField(null=True, blank=True)
	last_seen = models.DateTimeField(default=timezone.now)

	def __str__(self):
		return f"{self.domain.name} {self.record_type} {self.value}"


class DNSChangeLog(models.Model):
	CHANGE_TYPES = [
		('added', 'Added'),
		('removed', 'Removed'),
		('modified', 'Modified'),
	]

	domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='changelogs')
	record_type = models.CharField(max_length=10)
	name = models.CharField(max_length=253, blank=True)
	old_value = models.TextField(blank=True, null=True)
	new_value = models.TextField(blank=True, null=True)
	change_type = models.CharField(max_length=10, choices=CHANGE_TYPES)
	detected_at = models.DateTimeField(default=timezone.now)
	processed = models.BooleanField(default=False)

	class Meta:
		ordering = ['-detected_at']

	def __str__(self):
		return f"{self.domain.name} {self.change_type} @ {self.detected_at.isoformat()}"


class ThreatAlert(models.Model):
	SEVERITY = [
		('low', 'Low'),
		('medium', 'Medium'),
		('high', 'High'),
		('critical', 'Critical'),
	]

	domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='alerts')
	url = models.URLField(blank=True)
	reason = models.TextField()
	severity = models.CharField(max_length=10, choices=SEVERITY, default='medium')
	is_resolved = models.BooleanField(default=False)
	created_at = models.DateTimeField(default=timezone.now)
	resolved_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f"{self.domain.name} - {self.severity} - {self.reason[:40]}"


class BlockedURL(models.Model):
	SOURCE = [
		('auto', 'Automatic'),
		('manual', 'Manual'),
	]

	domain = models.ForeignKey(Domain, on_delete=models.SET_NULL, null=True, blank=True, related_name='blocked_urls')
	url = models.URLField()
	source = models.CharField(max_length=10, choices=SOURCE, default='auto')
	blocked_at = models.DateTimeField(default=timezone.now)
	expires_at = models.DateTimeField(null=True, blank=True)

	def __str__(self):
		return self.url


class Notification(models.Model):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
	alert = models.ForeignKey(ThreatAlert, on_delete=models.SET_NULL, null=True, blank=True)
	message = models.TextField()
	sent_at = models.DateTimeField(default=timezone.now)
	is_read = models.BooleanField(default=False)

	class Meta:
		ordering = ['-sent_at']

	def __str__(self):
		return f"Notification to {self.user} at {self.sent_at.isoformat()}"


class ScanEvent(models.Model):
    """Log when a domain is scanned (either by add or manual rescan).

    This is intentionally minimal: domain, scanned_at, and an optional payload
    summary stored as text for quick inspection.
    """
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='scans')
    scanned_at = models.DateTimeField(default=timezone.now)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['-scanned_at']

    def __str__(self):
        return f"Scan for {self.domain.name} at {self.scanned_at.isoformat()}"


class APIKey(models.Model):
    """User API keys for programmatic access and browser extension integration."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_keys')
    key = models.CharField(max_length=40, unique=True)  # Will be hashed in real deployments
    name = models.CharField(max_length=50, blank=True)  # User-friendly name
    prefix = models.CharField(max_length=10)  # First 10 chars for display
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"API Key for {self.user.username} ({self.name or 'Unnamed'})"


class AdultContentDomain(models.Model):
    """Stores blocked adult/pornographic websites and unwanted content domains."""
    CATEGORY_CHOICES = [
        ('pornography', 'Pornography'),
        ('nudity', 'Nudity'),
        ('adult_dating', 'Adult Dating'),
        ('illegal_content', 'Illegal Content'),
        ('malware', 'Malware/Phishing'),
        ('spam', 'Spam'),
    ]

    domain = models.CharField(max_length=253, unique=True, db_index=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='pornography')
    is_active = models.BooleanField(default=True)
    reason = models.TextField(blank=True, help_text='Why this domain is blocked')
    added_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-added_at']
        verbose_name = 'Adult Content Domain'
        verbose_name_plural = 'Adult Content Domains'

    def __str__(self):
        return f"{self.domain} ({self.category})"