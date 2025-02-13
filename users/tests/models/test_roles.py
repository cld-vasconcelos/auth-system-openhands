from django.test import TestCase
from users.models import Role


class TestRole(TestCase):
    def test_role_creation(self):
        role = Role.objects.create(name="Admin")
        assert str(role) == "Admin"
        assert Role.objects.count() == 1
