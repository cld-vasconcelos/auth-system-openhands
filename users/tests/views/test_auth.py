import pyotp
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from ..models import MFADevice

User = get_user_model()

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.password_reset_url = reverse('password_reset')
        self.password_reset_confirm_url = reverse('password_reset_confirm')
        self.mfa_enable_url = reverse('mfa_enable')
        self.mfa_verify_url = reverse('mfa_verify')

        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'TestPass123!',
            'password_confirm': 'TestPass123!'
        }

    def test_user_registration(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email=self.user_data['email']).exists())

    def test_user_login(self):
        # Create user
        User.objects.create_user(
            email=self.user_data['email'],
            username=self.user_data['username'],
            password=self.user_data['password']
        )

        # Login
        response = self.client.post(self.login_url, {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_logout(self):
        # Create and login user
        user = User.objects.create_user(
            email=self.user_data['email'],
            username=self.user_data['username'],
            password=self.user_data['password']
        )
        response = self.client.post(self.login_url, {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        })
        refresh_token = response.data['refresh']

        # Logout
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {response.data["access"]}')
        response = self.client.post(self.logout_url, {'refresh': refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_request(self):
        # Create user
        User.objects.create_user(
            email=self.user_data['email'],
            username=self.user_data['username'],
            password=self.user_data['password']
        )

        response = self.client.post(self.password_reset_url, {
            'email': self.user_data['email']
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_mfa_enable_and_verify(self):
        # Create and login user
        user = User.objects.create_user(
            email=self.user_data['email'],
            username=self.user_data['username'],
            password=self.user_data['password']
        )
        response = self.client.post(self.login_url, {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        })
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {response.data["access"]}')

        # Enable MFA
        response = self.client.post(self.mfa_enable_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('secret', response.data)
        self.assertIn('qr_code_uri', response.data)

        # Get MFA device
        mfa_device = MFADevice.objects.get(user=user)
        totp = pyotp.TOTP(mfa_device.secret_key)
        code = totp.now()

        # Verify MFA
        response = self.client.post(self.mfa_verify_url, {'code': code})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check user has MFA enabled
        user.refresh_from_db()
        self.assertTrue(user.two_factor_enabled)
