import pytest
from users.models import User, MFADevice


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
