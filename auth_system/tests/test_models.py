import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()

@pytest.mark.django_db
class TestUserModel:
    def test_create_user(self):
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        assert user.email == 'test@example.com'
        assert user.username == 'testuser'
        assert user.is_active
        assert not user.is_staff
        assert not user.is_superuser
        assert not user.is_email_verified
        assert not user.two_factor_enabled

    def test_create_superuser(self):
        admin_user = User.objects.create_superuser(
            email='admin@example.com',
            username='admin',
            password='admin123'
        )
        assert admin_user.email == 'admin@example.com'
        assert admin_user.username == 'admin'
        assert admin_user.is_active
        assert admin_user.is_staff
        assert admin_user.is_superuser

    def test_user_str_method(self):
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpass123'
        )
        assert str(user) == 'test@example.com'

    def test_create_user_without_email(self):
        with pytest.raises(ValueError):
            User.objects.create_user(
                email='',
                username='testuser',
                password='testpass123'
            )

    def test_email_is_normalized(self):
        email = 'test@EXAMPLE.COM'
        user = User.objects.create_user(
            email=email,
            username='testuser',
            password='testpass123'
        )
        assert user.email == email.lower()
