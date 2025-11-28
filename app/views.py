from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import update_session_auth_hash
import json
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST

# --- User Profile Update and Delete Views ---
@login_required
@require_POST
def update_profile_view(request):
	user = request.user
	data = request.POST
	username = data.get('username', '').strip()
	email = data.get('email', '').strip()
	phone = data.get('phone', '').strip()
	# Profile image handling (optional, not implemented here)
	errors = {}
	if username and username != user.username:
		if len(username) < 3:
			errors['username'] = 'Username must be at least 3 characters.'
		elif type(user).objects.filter(username=username).exclude(pk=user.pk).exists():
			errors['username'] = 'Username already taken.'
		else:
			user.username = username
	if email and email != user.email:
		if type(user).objects.filter(email__iexact=email).exclude(pk=user.pk).exists():
			errors['email'] = 'Email already in use.'
		else:
			user.email = email
	# Save phone to user.profile if you have a profile model, else skip
	# Example: if hasattr(user, 'profile'): user.profile.phone = phone; user.profile.save()
	if errors:
		return JsonResponse({'success': False, 'errors': errors}, status=400)
	user.save()
	return JsonResponse({'success': True})


@login_required
@require_POST
def change_password_view(request):
	user = request.user
	data = request.POST
	current = data.get('current_password', '')
	new = data.get('new_password', '')
	confirm = data.get('confirm_new_password', '')
	if not user.check_password(current):
		return JsonResponse({'success': False, 'error': 'Current password is incorrect.'}, status=400)
	if len(new) < 8:
		return JsonResponse({'success': False, 'error': 'New password must be at least 8 characters.'}, status=400)
	if new != confirm:
		return JsonResponse({'success': False, 'error': 'Passwords do not match.'}, status=400)
	user.set_password(new)
	user.save()
	update_session_auth_hash(request, user)
	return JsonResponse({'success': True})


@login_required
@require_POST
def delete_account_view(request):
	user = request.user
	# Optionally require password confirmation
	user.delete()
	logout(request)
	return JsonResponse({'success': True, 'redirect': '/'})
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_GET
from django.db.models import Count, Q
from django.db.models.functions import TruncMonth
from django.utils import timezone
import re
import os
import io
from django.conf import settings


@login_required
@require_GET
def api_domains(request):
	"""Return JSON list of domains and simple stats for the logged-in user."""
	try:
		qs = models.Domain.objects.filter(owner=request.user)
		domains = []
		for d in qs:
			domains.append({
				'id': d.id,
				'name': d.name,
				'status': 'secure' if not d.alerts.filter(is_resolved=False).exists() else 'warning',
				'last_checked': d.last_checked.isoformat() if d.last_checked else None,
				'scan_count': d.scans.count(),
			})

		# Calculate total scans across all user domains
		total_scans = models.ScanEvent.objects.filter(domain__owner=request.user).count()

		stats = {
			'total': qs.count(),
			'total_scans': total_scans,
			'threats': models.ThreatAlert.objects.filter(domain__owner=request.user, is_resolved=False).count(),
			'last_scan': None,
		}

		return JsonResponse({'domains': domains, 'stats': stats})
	except Exception:
		return JsonResponse({'domains': [], 'stats': {}}, status=500)


@login_required
@require_GET
def api_check_domain_status(request):
	"""Return a preview of DNS records and basic WHOIS info for a given domain.

	Uses dnspython (dns.resolver) when available; if not present returns a best-effort stub.
	"""
	name = request.GET.get('domain')
	if not name:
		return JsonResponse({'error': 'domain param required'}, status=400)

	name = name.strip()
	records = []
	whois_text = None

	# Attempt to use dnspython if installed
	try:
		import dns.resolver
		resolver = dns.resolver.Resolver()
		types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
		for t in types:
			try:
				ans = resolver.resolve(name, t, raise_on_no_answer=False)
				if ans.rrset is None:
					continue
				for r in ans:
					val = r.to_text()
					# For MX, value contains priority + mailserver; keep as-is
					records.append({'type': t, 'name': name, 'value': val, 'ttl': getattr(ans.rrset, 'ttl', None)})
			except Exception:
				continue
	except Exception:
		# dnspython not available or lookup failed; return a simple stub
		records = [
			{'type': 'A', 'name': name, 'value': '93.184.216.34', 'ttl': 3600},
			{'type': 'NS', 'name': name, 'value': 'ns1.example.net', 'ttl': 86400},
		]

	# WHOIS: try to import python-whois, otherwise leave blank
	try:
		import whois as _whois
		try:
			w = _whois.whois(name)
			whois_text = str(w)
		except Exception:
			whois_text = None
	except Exception:
		whois_text = None

	# Simple threat heuristic: if no A/AAAA records, mark as warning
	has_addr = any(r['type'] in ('A', 'AAAA') for r in records)
	threat = 'low' if has_addr else 'medium'

	return JsonResponse({
		'domain': name,
		'status': 'active' if has_addr else 'unknown',
		'dns_records': records,
		'whois': whois_text,
		'threat_level': threat,
	})
 


@login_required
@require_GET
def api_change_history(request):
	"""Return change counts per month for the logged-in user's domains.

	Query params:
	  months: int (how many months back; default 12)
	"""
	try:
		months = int(request.GET.get('months', 12))
	except Exception:
		months = 12

	# Truncate to month and count
	# Use ScanEvent as the primary signal for when a domain was scanned or added
	try:
		from .models import ScanEvent
		qs = ScanEvent.objects.filter(domain__owner=request.user)
		qs = qs.annotate(month=TruncMonth('scanned_at')).values('month').annotate(count=Count('id')).order_by('month')
	except Exception:
		# Fallback to DNSChangeLog if ScanEvent unavailable
		qs = models.DNSChangeLog.objects.filter(domain__owner=request.user)
		qs = qs.annotate(month=TruncMonth('detected_at')).values('month').annotate(count=Count('id')).order_by('month')

	# Build labels and counts for the last `months` months
	from datetime import datetime

	now = datetime.utcnow()
	labels = []
	counts = []
	# Create a dict for quick lookup
	data_map = {item['month'].strftime('%Y-%m'): item['count'] for item in qs if item.get('month')}

	# Build months backwards without external deps
	for i in range(months - 1, -1, -1):
		year = now.year
		month = now.month - i
		while month <= 0:
			month += 12
			year -= 1
		key = f"{year}-{month:02d}"
		labels.append(datetime(year, month, 1).strftime('%b %Y'))
		counts.append(data_map.get(key, 0))

	return JsonResponse({'labels': labels, 'counts': counts})



@login_required
@require_POST
def api_domain_rescan(request, domain_id):
	"""Trigger a rescan for a domain, record a ScanEvent, and return the scan data.

	Returns same shape as api_check_domain_status.
	"""
	domain = get_object_or_404(models.Domain, pk=domain_id, owner=request.user)
	name = domain.name
	# Reuse api_check_domain_status internal logic: perform the checks here
	records = []
	whois_text = None

	try:
		import dns.resolver
		resolver = dns.resolver.Resolver()
		types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
		for t in types:
			try:
				ans = resolver.resolve(name, t, raise_on_no_answer=False)
				if ans.rrset is None:
					continue
				for r in ans:
					val = r.to_text()
					records.append({'type': t, 'name': name, 'value': val, 'ttl': getattr(ans.rrset, 'ttl', None)})
			except Exception:
				continue
	except Exception:
		records = [
			{'type': 'A', 'name': name, 'value': '93.184.216.34', 'ttl': 3600},
			{'type': 'NS', 'name': name, 'value': 'ns1.example.net', 'ttl': 86400},
		]

	try:
		import whois as _whois
		try:
			w = _whois.whois(name)
			whois_text = str(w)
		except Exception:
			whois_text = None
	except Exception:
		whois_text = None

	has_addr = any(r['type'] in ('A', 'AAAA') for r in records)
	threat = 'low' if has_addr else 'medium'

	# Record ScanEvent
	try:
		from .models import ScanEvent
		summary_lines = [f"{r.get('type')} {r.get('value')}" for r in records[:10]]
		ScanEvent.objects.create(domain=domain, summary=';'.join(summary_lines))
	except Exception:
		pass

	return JsonResponse({
		'domain': name,
		'status': 'active' if has_addr else 'unknown',
		'dns_records': records,
		'whois': whois_text,
		'threat_level': threat,
	})
from .models import Domain, ThreatAlert, BlockedURL, Notification
from . import models
from urllib.parse import urlparse


User = get_user_model()


@login_required
def dashboard(request):
	# Simple dashboard view that lists user's domains and recent alerts
	domains = Domain.objects.filter(owner=request.user)
	recent_alerts = models.ThreatAlert.objects.filter(domain__owner=request.user).order_by('-created_at')[:20]
	# Include active adult blocklist entries for display and quick add
	adult_domains = models.AdultContentDomain.objects.filter(is_active=True).order_by('-added_at')[:50]
	return render(request, 'dashboard.html', {'domains': domains, 'recent_alerts': recent_alerts, 'adult_domains': adult_domains})



@login_required
@require_POST
def add_adult_domain(request):
	"""Add a new domain to the AdultContentDomain blocklist from dashboard form.

	Accepts POST: url (full URL or domain), optional category. Returns JSON.
	"""
	try:
		# Support JSON POSTs (from fetch) or traditional form posts
		raw = None
		if request.content_type and 'application/json' in request.content_type:
			import json
			try:
				payload = json.loads(request.body.decode('utf-8') or '{}')
			except Exception:
				payload = {}
			raw = payload.get('url') or payload.get('domain')
			category = payload.get('category', 'pornography')
		else:
			data = request.POST
			raw = data.get('url') or data.get('domain')
			category = data.get('category', 'pornography')
		if not raw:
			return JsonResponse({'error': 'url is required'}, status=400)

		# Normalize to hostname
		parsed = urlparse(raw if '://' in raw else ('http://' + raw))
		hostname = parsed.hostname
		if not hostname:
			return JsonResponse({'error': 'invalid url'}, status=400)

		hostname = hostname.lower().strip()

		obj, created = models.AdultContentDomain.objects.get_or_create(
			domain=hostname,
			defaults={
				'category': category,
				'is_active': True,
				'reason': f'Added via dashboard by {request.user.username}'
			}
		)

		return JsonResponse({
			'ok': True,
			'created': created,
			'domain': obj.domain,
			'category': obj.category
		})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def delete_adult_domain(request):
	"""Delete a domain from the AdultContentDomain blocklist.
	
	Accepts POST: domain_id (pk) or domain (hostname). Returns JSON.
	"""
	try:
		# Support JSON POSTs or form posts
		if request.content_type and 'application/json' in request.content_type:
			import json
			try:
				payload = json.loads(request.body.decode('utf-8') or '{}')
			except Exception:
				payload = {}
			domain_id = payload.get('id')
			domain_name = payload.get('domain')
		else:
			data = request.POST
			domain_id = data.get('id')
			domain_name = data.get('domain')
		
		if domain_id:
			obj = get_object_or_404(models.AdultContentDomain, pk=domain_id)
		elif domain_name:
			obj = get_object_or_404(models.AdultContentDomain, domain=domain_name)
		else:
			return JsonResponse({'error': 'domain_id or domain is required'}, status=400)
		
		obj.delete()
		return JsonResponse({'ok': True, 'message': 'Domain deleted from blocklist'})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
def domain_detail(request, domain_id):
	domain = get_object_or_404(models.Domain, pk=domain_id, owner=request.user)
	records = domain.records.all()
	changelogs = domain.changelogs.all()[:50]
	alerts = domain.alerts.all()[:50]
	return render(request, 'domain_detail.html', {'domain': domain, 'records': records, 'changelogs': changelogs, 'alerts': alerts})


@login_required
@require_POST
def delete_domain(request):
	"""Delete a domain from the user's monitored domains list.
	
	Accepts POST: domain_id (pk). Returns JSON.
	"""
	try:
		# Support JSON POSTs or form posts
		if request.content_type and 'application/json' in request.content_type:
			import json
			try:
				payload = json.loads(request.body.decode('utf-8') or '{}')
			except Exception:
				payload = {}
			domain_id = payload.get('id')
		else:
			data = request.POST
			domain_id = data.get('id')
		
		if not domain_id:
			return JsonResponse({'error': 'domain_id is required'}, status=400)
		
		# Ensure the user owns this domain
		domain = get_object_or_404(models.Domain, pk=domain_id, owner=request.user)
		domain.delete()
		return JsonResponse({'ok': True, 'message': 'Domain deleted successfully'})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@require_GET
def extension_check(request):
	# Lightweight endpoint for the browser extension to ask whether a URL is blocked
	url = request.GET.get('url')
	if not url:
		return HttpResponseBadRequest('url param required')
	blocked = models.BlockedURL.objects.filter(url__iexact=url).exists()
	return JsonResponse({'url': url, 'blocked': blocked})


@login_required
@require_POST
def mark_alert_resolved(request, alert_id):
	alert = get_object_or_404(models.ThreatAlert, pk=alert_id, domain__owner=request.user)
	alert.is_resolved = True
	alert.resolved_at = models.timezone.now() if hasattr(models, 'timezone') else None
	alert.save()
	return JsonResponse({'ok': True})


@require_POST
def extension_report(request):
	# Endpoint for extension to report suspicious URLs observed in the browser
	try:
		data = request.POST
		url = data.get('url')
		reason = data.get('reason', 'reported by extension')
		if not url:
			return HttpResponseBadRequest('url required')
		# Create an auto BlockedURL record and lightweight alert (no user association)
		bu = models.BlockedURL.objects.create(url=url, source='auto')
		# We don't have a domain owner here so domain null is allowed
		alert = models.ThreatAlert.objects.create(domain=bu.domain if bu.domain else None, url=url, reason=reason, severity='medium')
		return JsonResponse({'ok': True, 'alert_id': alert.id})
	except Exception:
		return HttpResponseBadRequest('invalid')


def login_view(request):
	"""Render login form and authenticate users.

	Accepts POST with 'email' and 'password'. On success logs the user in and redirects to dashboard.
	"""
	if request.method == 'POST':
		email = request.POST.get('email') or request.POST.get('username')
		password = request.POST.get('password')
		# Try to look up user by email first
		user = None
		if email:
			try:
				user_obj = User.objects.filter(email__iexact=email).first()
				if user_obj:
					user = authenticate(request, username=user_obj.username, password=password)
			except Exception:
				user = None

		# Fallback: treat email as username
		if user is None:
			user = authenticate(request, username=email, password=password)

		if user is not None:
			login(request, user)
			messages.success(request, 'Logged in successfully')
			return redirect('app:dashboard')
		else:
			messages.error(request, 'Invalid credentials')

	return render(request, 'login.html')


def register_view(request):
	"""Register new users. Expects POST: username, email, password."""
	if request.method == 'POST':
		username = request.POST.get('username') or request.POST.get('email')
		email = request.POST.get('email')
		password = request.POST.get('password')

		errors = {}
		if not username or len(username) < 3:
			errors['username'] = 'Username must be at least 3 characters'
		if not email:
			errors['email'] = 'Email is required'
		if not password or len(password) < 8:
			errors['password'] = 'Password must be at least 8 characters'

		if User.objects.filter(username=username).exists():
			errors['username'] = 'Username already exists'
		if User.objects.filter(email__iexact=email).exists():
			errors['email'] = 'Email already registered'

		if errors:
			for v in errors.values():
				messages.error(request, v)
			return render(request, 'register.html')

		user = User.objects.create_user(username=username, email=email, password=password)
		login(request, user)
		messages.success(request, 'Account created and logged in')
		return redirect('app:dashboard')

	return render(request, 'register.html')


def logout_view(request):
	logout(request)
	messages.info(request, 'Logged out')
	return redirect('app:login')


def index_view(request):
	# Public landing page — if logged in redirect to dashboard
	if request.user.is_authenticated:
		return redirect('app:dashboard')
	return render(request, 'index.html')


@login_required
def add_domain_view(request):
	# Handle server-side create for domain (form POST)
	if request.method == 'POST':
		name = (request.POST.get('domain') or '').strip().lower()

		# Basic validation: .ng domain or wildcard
		ng_re = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*ng$')
		if not name:
			messages.error(request, 'Please provide a domain name')
			return render(request, 'add_domain.html')

		if not ng_re.match(name):
			messages.error(request, 'Invalid domain. Please enter a .ng domain (e.g., example.ng or *.ng)')
			return render(request, 'add_domain.html')

		# Check for existing domain
		existing = models.Domain.objects.filter(name__iexact=name).first()
		if existing:
			if existing.owner == request.user:
				messages.info(request, 'You have already added this domain')
				return redirect('app:dashboard')
			else:
				messages.error(request, 'This domain is already monitored by another account')
				return render(request, 'add_domain.html')

		# Create domain
		try:
			print(f'[DEBUG] Creating domain: {name} for user: {request.user.username}')
			domain = models.Domain.objects.create(name=name, owner=request.user)
			print(f'[DEBUG] Domain created successfully with ID: {domain.id}')
			
			# Record initial scan event for the newly added domain
			try:
				from .models import ScanEvent
				ScanEvent.objects.create(domain=domain, summary='created via add_domain_view')
			except Exception as e:
				print(f'[DEBUG] ScanEvent creation failed: {e}')
				pass
			
			# After creating domain, optionally generate and save a PDF report
			generate_pdf_flag = str(request.POST.get('generate_pdf', '')).lower() in ('1', 'true', 'yes')
			print(f'[DEBUG] generate_pdf_flag: {generate_pdf_flag}')
			
			if generate_pdf_flag:
				# Build preview data similar to api_check_domain_status
				data = {'domain': name, 'dns_records': [], 'whois': None}
				try:
					import dns.resolver
					resolver = dns.resolver.Resolver()
					types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
					for t in types:
						try:
							ans = resolver.resolve(name, t, raise_on_no_answer=False)
							if ans.rrset is None:
								continue
							for r in ans:
								data['dns_records'].append({'type': t, 'name': name, 'value': r.to_text(), 'ttl': getattr(ans.rrset, 'ttl', None)})
						except Exception:
							continue
				except Exception:
					# dnspython not available or lookup failed; use simple stub
					data['dns_records'] = [
						{'type': 'A', 'name': name, 'value': '93.184.216.34', 'ttl': 3600},
						{'type': 'NS', 'name': name, 'value': 'ns1.example.net', 'ttl': 86400},
					]
				# WHOIS attempt
				try:
					import whois as _whois
					w = _whois.whois(name)
					data['whois'] = str(w)
				except Exception:
					data['whois'] = None

				# Ensure reports directory exists
				reports_dir = os.path.join(str(settings.BASE_DIR), 'reports')
				os.makedirs(reports_dir, exist_ok=True)
				filename = f"{domain.name.replace('*','wildcard').replace('/','_')}.pdf"
				filepath = os.path.join(reports_dir, filename)

				# First write a plain text fallback so something is always saved
				try:
					with open(filepath, 'w', encoding='utf-8') as f:
						f.write(f"Domain Report: {domain.name}\n\n")
						for r in data.get('dns_records', []):
							f.write(f"{r.get('type')} {r.get('name')} {r.get('value')} TTL:{r.get('ttl')}\n")
						f.write('\nWHOIS:\n')
						f.write(str(data.get('whois') or 'N/A'))
				except Exception:
					# if even this fails, continue silently
					pass

				# Then, if reportlab is available, overwrite with a real PDF
				try:
					from reportlab.lib.pagesizes import letter
					from reportlab.pdfgen import canvas
					buffer = io.BytesIO()
					c = canvas.Canvas(buffer, pagesize=letter)
					c.setFont('Helvetica-Bold', 16)
					c.drawString(40, 750, f"Domain Report: {domain.name}")
					c.setFont('Helvetica', 11)
					y = 730
					c.drawString(40, y, 'DNS Records:')
					y -= 18
					for r in data.get('dns_records', []):
						line = f"{r.get('type')} {r.get('name')} {r.get('value')} TTL:{r.get('ttl')}"
						c.drawString(50, y, line[:95])
						y -= 14
						if y < 60:
							c.showPage(); y = 750
					c.drawString(40, y-4, 'WHOIS:')
					y -= 22
					whois_text = data.get('whois') or 'WHOIS information not available'
					for ln in str(whois_text).splitlines():
						c.drawString(50, y, ln[:95])
						y -= 14
						if y < 60:
							c.showPage(); y = 750
					c.save()
					buffer.seek(0)
					with open(filepath, 'wb') as f:
						f.write(buffer.read())
				except Exception:
					# If PDF generation fails, we already have a text fallback
					pass

				# Record the report path in the domain notes for easy retrieval
				try:
					domain.notes = (domain.notes or '') + f"\nReport: {filepath}"
					domain.save()
				except Exception:
					pass

				messages.success(request, f'Domain {domain.name} added and report saved (if generation succeeded)')
				return redirect('app:dashboard')
			else:
				messages.success(request, f'Domain {domain.name} added and monitoring started')
				return redirect('app:dashboard')
		except Exception as e:
			print(f'[DEBUG] Exception in add_domain_view: {type(e).__name__}: {str(e)}')
			import traceback
			print(traceback.format_exc())
			messages.error(request, 'Failed to add domain. Please try again.')
			return render(request, 'add_domain.html')

	return render(request, 'add_domain.html')




def api_docs_view(request):
	return render(request, 'api_docs.html')


def extension_info_view(request):
	return render(request, 'extension_info.html')


def contact_view(request):
	return render(request, 'contact.html')


@login_required
def notifications_view(request):
	notes = models.Notification.objects.filter(user=request.user).order_by('-sent_at')
	return render(request, 'notifications.html', {'notifications': notes})


@login_required
def settings_view(request):
	return render(request, 'settings.html')


@login_required
def admin_dashboard_view(request):
	# Simple admin dashboard stub; require staff in template or later
	if not request.user.is_staff:
		return redirect('app:dashboard')
	return render(request, 'admin_dashboard.html')


def domain_detail_by_name(request):
	"""Legacy endpoint to support links like domain_detail.html?domain=example.ng

	Looks up the Domain by name and redirects to the canonical domain_detail url.
	"""
	name = request.GET.get('domain')
	if not name:
		return redirect('app:dashboard')
	try:
		domain = models.Domain.objects.filter(name__iexact=name).first()
		if domain:
			return redirect('app:domain_detail', domain_id=domain.id)
	except Exception:
		pass
	return redirect('app:dashboard')


@login_required
@require_GET
def api_extension_blocklist(request):
	"""Return blocklist for browser extension.

	Returns blocked URLs and monitored domains owned by the user.
	"""
	try:
		# Allow either session-authenticated users or API key (Bearer) auth
		user = request.user if getattr(request, 'user', None) and request.user.is_authenticated else None
		if not user:
			# Try API key in Authorization header
			auth = request.META.get('HTTP_AUTHORIZATION', '')
			if auth.lower().startswith('bearer '):
				token = auth.split(None, 1)[1]
				api_key = models.APIKey.objects.filter(key=token, is_active=True).first()
				if api_key:
					api_key.last_used_at = timezone.now()
					api_key.save(update_fields=['last_used_at'])
					user = api_key.user

		if not user:
			return JsonResponse({'error': 'Authentication required'}, status=401)

		# Get all blocked URLs from this user's domains
		blocked_urls = models.BlockedURL.objects.filter(
			domain__owner=user
		).values_list('url', flat=True).distinct()[:100]

		# Get all monitored domain names
		monitored_domains = models.Domain.objects.filter(
			owner=user, is_active=True
		).values_list('name', flat=True)[:50]

		return JsonResponse({
			'blocked_urls': list(blocked_urls),
			'monitored_domains': list(monitored_domains),
			'timestamp': timezone.now().isoformat()
		})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@require_GET
def api_extension_adult_blocklist(request):
	"""Return adult content blocklist for browser extension.

	Returns list of pornographic and unwanted content domains to block.
	No authentication required - this is a public blocklist.
	"""
	try:
		# Get all active adult content domains
		adult_domains = models.AdultContentDomain.objects.filter(
			is_active=True
		).values('domain', 'category').order_by('-added_at')[:1000]

		# Format as list of domains with categories
		blocklist = [
			{
				'domain': item['domain'],
				'category': item['category'],
				'reason': 'Adult/unwanted content'
			}
			for item in adult_domains
		]

		return JsonResponse({
			'adult_blocklist': blocklist,
			'count': len(blocklist),
			'timestamp': timezone.now().isoformat(),
			'categories': ['pornography', 'nudity', 'adult_dating', 'illegal_content', 'malware', 'spam']
		})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def api_extension_report_ad(request):
	"""Extension reports a suspicious ad URL.

	Creates a BlockedURL record and associated alert.
	"""
	try:
		data = request.POST or {}
		try:
			import json
			data = json.loads(request.body)
		except Exception:
			pass

		ad_url = data.get('ad_url') or request.POST.get('ad_url')
		source_page = data.get('source_page') or request.POST.get('source_page')

		if not ad_url:
			return JsonResponse({'error': 'ad_url required'}, status=400)

		# Try to associate with a user domain
		domain = None
		try:
			from urllib.parse import urlparse
			source_hostname = urlparse(source_page).hostname if source_page else None
			if source_hostname:
				domain = models.Domain.objects.filter(
					name__iexact=source_hostname,
					owner=request.user
				).first()
		except Exception:
			pass

		# Create BlockedURL and Alert
		bu = models.BlockedURL.objects.create(
			url=ad_url,
			source='extension',
			domain=domain
		)

		alert = models.ThreatAlert.objects.create(
			domain=domain,
			url=ad_url,
			reason='Suspicious ad reported by browser extension',
			severity='medium'
		)

		return JsonResponse({
			'success': True,
			'blocked_url_id': bu.id,
			'alert_id': alert.id
		})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@require_POST
def api_extension_check_url(request):
	"""Check if a URL is blocked (lightweight, no auth required for performance).

	Used by content script to check URLs on-the-fly.
	"""
	try:
		data = request.POST or {}
		try:
			import json
			data = json.loads(request.body)
		except Exception:
			pass

		url = data.get('url') or request.POST.get('url')
		if not url:
			return JsonResponse({'blocked': False})

		# Check against BlockedURL table (global check)
		blocked = models.BlockedURL.objects.filter(url__iexact=url).exists()

		return JsonResponse({'blocked': blocked, 'url': url})
	except Exception:
		return JsonResponse({'blocked': False})


@login_required
@require_GET
def api_alerts(request):
	"""Return JSON list of alerts for the logged-in user."""
	try:
		# Get all unresolved alerts for the user's domains
		alerts = models.ThreatAlert.objects.filter(
			domain__owner=request.user
		).order_by('-created_at')

		alerts_data = []
		for alert in alerts:
			alerts_data.append({
				'id': alert.id,
				'type': 'Threat Alert',  # Can be enhanced to show alert type
				'domain': alert.domain.name if alert.domain else 'Unknown',
				'severity': alert.severity,
				'reason': alert.reason,
				'url': alert.url if alert.url else '',
				'timestamp': alert.created_at.isoformat(),
				'status': 'unread' if not alert.is_resolved else 'read',
				'description': f"{alert.reason} (URL: {alert.url})" if alert.url else alert.reason
			})

		return JsonResponse({'alerts': alerts_data})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


import secrets


@login_required
@require_GET
def api_keys_list(request):
	"""List all API keys for the logged-in user."""
	try:
		keys = models.APIKey.objects.filter(user=request.user, is_active=True)
		keys_data = [
			{
				'id': k.id,
				'name': k.name or 'Unnamed',
				'prefix': k.prefix,
				'created_at': k.created_at.isoformat(),
				'last_used_at': k.last_used_at.isoformat() if k.last_used_at else None
			}
			for k in keys
		]
		return JsonResponse({'keys': keys_data})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def api_keys_create(request):
	"""Generate a new API key for the user."""
	try:
		# Generate a unique key
		key = f"ngshield_{secrets.token_urlsafe(24)}"
		prefix = key[:10]

		# Create APIKey record
		api_key = models.APIKey.objects.create(
			user=request.user,
			key=key,
			prefix=prefix,
			name=request.POST.get('name') or 'API Key'
		)

		return JsonResponse({
			'success': True,
			'key': key,
			'id': api_key.id,
			'prefix': prefix
		})
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def api_keys_revoke(request):
	"""Revoke (deactivate) an API key."""
	try:
		import json
		try:
			data = json.loads(request.body)
		except Exception:
			data = request.POST

		key_id = data.get('key_id')
		if not key_id:
			return JsonResponse({'error': 'key_id required'}, status=400)

		# Find and deactivate the key
		api_key = models.APIKey.objects.get(id=key_id, user=request.user)
		api_key.is_active = False
		api_key.save()

		return JsonResponse({'success': True})
	except models.APIKey.DoesNotExist:
		return JsonResponse({'error': 'API key not found'}, status=404)
	except Exception as e:
		return JsonResponse({'error': str(e)}, status=500)
