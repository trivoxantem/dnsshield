from django.contrib import admin
from . import models


@admin.register(models.Domain)
class DomainAdmin(admin.ModelAdmin):
	list_display = ('name', 'owner', 'is_active', 'registered_on', 'last_checked')
	search_fields = ('name', 'owner__username')
	list_filter = ('is_active',)


@admin.register(models.DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
	list_display = ('domain', 'record_type', 'name', 'value', 'last_seen')
	search_fields = ('domain__name', 'value')
	list_filter = ('record_type',)


@admin.register(models.DNSChangeLog)
class DNSChangeLogAdmin(admin.ModelAdmin):
	list_display = ('domain', 'change_type', 'record_type', 'detected_at', 'processed')
	search_fields = ('domain__name', 'old_value', 'new_value')
	list_filter = ('change_type', 'processed')


@admin.register(models.ThreatAlert)
class ThreatAlertAdmin(admin.ModelAdmin):
	list_display = ('domain', 'severity', 'is_resolved', 'created_at')
	search_fields = ('domain__name', 'reason')
	list_filter = ('severity', 'is_resolved')


@admin.register(models.BlockedURL)
class BlockedURLAdmin(admin.ModelAdmin):
	list_display = ('url', 'domain', 'source', 'blocked_at')
	search_fields = ('url',)
	list_filter = ('source',)


@admin.register(models.Notification)
class NotificationAdmin(admin.ModelAdmin):
	list_display = ('user', 'alert', 'sent_at', 'is_read')
	search_fields = ('user__username', 'message')
	list_filter = ('is_read',)


@admin.register(models.AdultContentDomain)
class AdultContentDomainAdmin(admin.ModelAdmin):
	list_display = ('domain', 'category', 'is_active', 'added_at')
	search_fields = ('domain',)
	list_filter = ('category', 'is_active')
	readonly_fields = ('added_at', 'updated_at')
	fieldsets = (
		('Domain Information', {
			'fields': ('domain', 'category', 'is_active')
		}),
		('Details', {
			'fields': ('reason', 'added_at', 'updated_at'),
			'classes': ('collapse',)
		}),
	)
