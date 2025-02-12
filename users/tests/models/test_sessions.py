import pytest
from django.utils import timezone
from datetime import timedelta
from users.models import User, Session


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
