from django.test import TestCase
from users.models import User, Role, UserRole


class TestUserRole(TestCase):
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
