import pyotp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.utils import timezone
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .models import Session, MFADevice
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    MFAEnableSerializer,
    MFAVerifySerializer,
)

User = get_user_model()

class RegisterView(APIView):
    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        mfa_code = serializer.validated_data.get('mfa_code')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.check_password(password):
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if user.two_factor_enabled:
            if not mfa_code:
                return Response(
                    {"error": "MFA code required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            mfa_device = MFADevice.objects.get(user=user)
            totp = pyotp.TOTP(mfa_device.secret_key)
            if not totp.verify(mfa_code):
                return Response(
                    {"error": "Invalid MFA code"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Create session
        session = Session.objects.create(
            user=user,
            token=str(refresh),
            expires_at=timezone.now() + refresh.lifetime
        )

        return Response({
            'access': access_token,
            'refresh': str(refresh)
        })

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Invalidate session
            Session.objects.filter(token=refresh_token).delete()

            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"error": "Invalid token"},
                status=status.HTTP_400_BAD_REQUEST
            )

class PasswordResetView(APIView):
    @method_decorator(ratelimit(key='ip', rate='3/m', method=['POST']))
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = get_random_string(64)
            user.set_password(token)
            user.save()

            # Send reset email
            send_mail(
                'Password Reset',
                f'Your password reset token is: {token}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            return Response(
                {"message": "Password reset instructions sent"},
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return Response(
                {"message": "Password reset instructions sent"},
                status=status.HTTP_200_OK
            )

class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data['token']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(password=token)
            user.set_password(password)
            user.save()
            return Response(
                {"message": "Password reset successful"},
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid token"},
                status=status.HTTP_400_BAD_REQUEST
            )

class MFAEnableView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if hasattr(request.user, 'mfa_device'):
            return Response(
                {"error": "MFA is already enabled"},
                status=status.HTTP_400_BAD_REQUEST
            )

        secret = pyotp.random_base32()
        mfa_device = MFADevice.objects.create(
            user=request.user,
            secret_key=secret
        )

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            request.user.email,
            issuer_name="OpenHands Auth"
        )

        return Response({
            "secret": secret,
            "qr_code_uri": provisioning_uri
        })

class MFAVerifyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        code = serializer.validated_data['code']
        mfa_device = request.user.mfa_device

        totp = pyotp.TOTP(mfa_device.secret_key)
        if totp.verify(code):
            request.user.two_factor_enabled = True
            request.user.save()
            return Response({"message": "MFA enabled successfully"})

        return Response(
            {"error": "Invalid MFA code"},
            status=status.HTTP_400_BAD_REQUEST
        )
