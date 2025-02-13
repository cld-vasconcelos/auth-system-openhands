from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/password-reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('auth/password-reset-confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('auth/mfa/enable/', views.MFAEnableView.as_view(), name='mfa_enable'),
    path('auth/mfa/verify/', views.MFAVerifyView.as_view(), name='mfa_verify'),
]
