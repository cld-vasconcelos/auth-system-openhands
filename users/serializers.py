from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import MFADevice

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="User's password (must meet complexity requirements)"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Password confirmation (must match password)"
    )

    class Meta:
        model = User
        fields = ('email', 'username', 'password', 'password_confirm')
        extra_kwargs = {
            'email': {'help_text': "User's email address"},
            'username': {'help_text': "User's desired username"}
        }

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data['password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="User's email address"
    )
    password = serializers.CharField(
        help_text="User's password"
    )
    mfa_code = serializers.CharField(
        required=False,
        help_text="6-digit MFA code (required if MFA is enabled)"
    )

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Email address of the account to reset password"
    )

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(
        help_text="Password reset token received via email"
    )
    password = serializers.CharField(
        write_only=True,
        help_text="New password (must meet complexity requirements)"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        help_text="New password confirmation (must match password)"
    )

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data['password'])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data

class MFAEnableSerializer(serializers.ModelSerializer):
    """
    Serializer for enabling MFA. Returns the secret key and QR code URI.
    """
    class Meta:
        model = MFADevice
        fields = ('secret_key',)
        read_only_fields = ('secret_key',)
        extra_kwargs = {
            'secret_key': {'help_text': 'TOTP secret key for MFA setup'}
        }

class MFAVerifySerializer(serializers.Serializer):
    code = serializers.CharField(
        help_text="6-digit TOTP verification code"
    )
