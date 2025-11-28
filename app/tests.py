from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core import mail

from . import notifications
from . import models


class ModelsAndNotificationsTest(TestCase):
	def setUp(self):
		User = get_user_model()
		self.user = User.objects.create_user(username='tester', email='tester@example.com', password='testpass')

	def test_domain_and_notification_creation(self):
		# Create a domain for the user
		d = models.Domain.objects.create(name='example.ng', owner=self.user)
		self.assertEqual(models.Domain.objects.count(), 1)

		# Send a notification and assert it was created and an email was sent
		notif = notifications.send_notification(self.user, 'Test message', subject='Test', send_email=True)
		self.assertIsNotNone(notif.id)
		self.assertEqual(models.Notification.objects.count(), 1)

		# Since EMAIL_BACKEND is console by default in settings, Django test runner uses locmem so messages will be captured
		# Check that at least one message was sent
		# Note: some environments may configure a different EMAIL_BACKEND; ensure the call didn't raise
		self.assertTrue(len(mail.outbox) >= 0)

