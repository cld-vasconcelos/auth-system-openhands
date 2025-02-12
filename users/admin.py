from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'username', 'is_email_verified', 'is_active', 'is_staff', 'created_at')
    list_filter = ('is_active', 'is_staff', 'is_email_verified', 'two_factor_enabled')
    search_fields = ('email', 'username')
    ordering = ('email',)
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        (_('Profile'), {'fields': ('profile_picture', 'is_email_verified', 'two_factor_enabled')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'created_at', 'updated_at')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2'),
        }),
    )
