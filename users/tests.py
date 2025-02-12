from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()


class UserModelTests(TestCase):
    def test_create_user(self):
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(user.check_password('testpass123'))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_email_verified)
        self.assertFalse(user.two_factor_enabled)

    def test_create_superuser(self):
        admin_user = User.objects.create_superuser(
            email='admin@example.com',
            username='admin',
            password='admin123'
        )
        self.assertEqual(admin_user.email, 'admin@example.com')
        self.assertEqual(admin_user.username, 'admin')
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)

    def test_email_is_required(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', username='testuser', password='test123')

    def test_email_is_normalized(self):
        email = 'test@EXAMPLE.COM'
        user = User.objects.create_user(email=email, username='testuser', password='test123')
        self.assertEqual(user.email, email.lower())

    def test_unique_email(self):
        User.objects.create_user(email='test@example.com', username='testuser1', password='test123')
        with self.assertRaises(Exception):
            User.objects.create_user(email='test@example.com', username='testuser2', password='test123')
