import pytest
from users.models import Role


@pytest.mark.django_db
class TestRole:
    def test_role_creation(self):
        role = Role.objects.create(name="Admin")
        assert str(role) == "Admin"
        assert Role.objects.count() == 1
