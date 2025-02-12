import pytest
from django.utils import timezone
from datetime import timedelta
from users.models import User, Role, UserRole, Session, MFADevice


@pytest.mark.django_db
class TestRole:
    def test_role_creation(self):
        role = Role.objects.create(name="Admin")
        assert str(role) == "Admin"
        assert Role.objects.count() == 1


@pytest.mark.django_db
class TestUserRole:
    def test_user_role_creation(self):
        user = User.objects.create_user(
            email="test@example.com",
            username="testuser",
            password="testpass123"
        )
        role = Role.objects.create(name="User")
        user_role = UserRole.objects.create(user=user, role=role)
        assert str(user_role) == "test@example.com - User"
        assert UserRole.objects.count() == 1


@pytest.mark.django_db
class TestSession:
    def test_session_creation(self):
        user = User.objects.create_user(
            email="test@example.com",
            username="testuser",
            password="testpass123"
        )
        expires_at = timezone.now() + timedelta(days=1)
        session = Session.objects.create(
            user=user,
            token="test-token",
            expires_at=expires_at
        )
        assert not session.is_expired
        assert Session.objects.count() == 1

    def test_session_expiry(self):
        user = User.objects.create_user(
            email="test@example.com",
            username="testuser",
            password="testpass123"
        )
        expires_at = timezone.now() - timedelta(minutes=1)
        session = Session.objects.create(
            user=user,
            token="test-token",
            expires_at=expires_at
        )
        assert session.is_expired


@pytest.mark.django_db
class TestMFADevice:
    def test_mfa_device_creation(self):
        user = User.objects.create_user(
            email="test@example.com",
            username="testuser",
            password="testpass123"
        )
        mfa_device = MFADevice.objects.create(
            user=user,
            secret_key="test-secret-key"
        )
        assert str(mfa_device) == "MFA Device for test@example.com"
        assert MFADevice.objects.count() == 1
