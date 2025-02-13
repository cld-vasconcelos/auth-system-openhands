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
    """
    Register a new user.

    Accepts POST requests with the following data:
    * email - User's email address
    * username - User's desired username
    * password - User's password
    * password_confirm - Password confirmation
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer

    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request):
        """
        Create a new user account.

        Returns:
            201: User registered successfully
            400: Invalid input data
        """
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    """
    Authenticate a user and return JWT tokens.

    Accepts POST requests with the following data:
    * email - User's email address
    * password - User's password
    * mfa_code - MFA verification code (required if MFA is enabled)
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer

    @method_decorator(ratelimit(key='ip', rate='5/m', method=['POST']))
    def post(self, request):
        """
        Authenticate user and return tokens.

        Returns:
            200: Authentication successful, returns access and refresh tokens
            400: Invalid input data
            401: Invalid credentials or MFA code
        """
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
    """
    Logout user by invalidating their refresh token.

    Accepts POST requests with the following data:
    * refresh - JWT refresh token to invalidate
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Invalidate refresh token and logout user.

        Returns:
            200: Successfully logged out
            400: Invalid token
        """
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
    """
    Request a password reset email.

    Accepts POST requests with the following data:
    * email - Email address of the account to reset password
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer

    @method_decorator(ratelimit(key='ip', rate='3/m', method=['POST']))
    def post(self, request):
        """
        Send password reset instructions via email.

        Returns:
            200: Password reset instructions sent
            400: Invalid input data
        """
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
    """
    Confirm password reset and set new password.

    Accepts POST requests with the following data:
    * token - Password reset token received via email
    * password - New password
    * password_confirm - New password confirmation
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        """
        Reset password using the provided token.

        Returns:
            200: Password reset successful
            400: Invalid token or password validation failed
        """
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
    """
    Enable Multi-Factor Authentication (MFA) for the authenticated user.

    Returns:
    * secret - MFA secret key for TOTP setup
    * qr_code_uri - QR code URI for scanning with authenticator app
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MFAEnableSerializer

    def post(self, request):
        """
        Generate MFA secret and QR code URI.

        Returns:
            200: MFA setup data returned successfully
            400: MFA is already enabled
        """
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
    """
    Verify MFA code and enable MFA for the authenticated user.

    Accepts POST requests with the following data:
    * code - 6-digit TOTP verification code
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MFAVerifySerializer

    def post(self, request):
        """
        Verify MFA code and enable MFA.

        Returns:
            200: MFA enabled successfully
            400: Invalid MFA code or validation failed
        """
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
