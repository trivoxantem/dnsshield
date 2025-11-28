from django.core.mail import send_mail
from django.conf import settings

from .models import Notification


def send_notification(user, message, subject=None, alert=None, send_email=True):
    """Create a Notification record and optionally send an email.

    Args:
        user: Django user instance to notify.
        message: Text message body.
        subject: Email subject. Defaults to a short subject.
        alert: Optional ThreatAlert instance related to this notification.
        send_email: If True, an email will be sent using Django's EMAIL_* settings.
    Returns:
        Notification instance.
    """
    if subject is None:
        subject = f"NGShield notification for {user.username}"

    notif = Notification.objects.create(user=user, alert=alert, message=message)

    if send_email and user.email:
        try:
            send_mail(
                subject,
                message,
                getattr(settings, 'NOTIFICATION_EMAIL_FROM', settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'no-reply@dnsshield.local'),
                [user.email],
                fail_silently=False,
            )
        except Exception:
            # Don't raise on email failure; notification is persisted
            pass

    return notif
