from django.urls import path
from .views import RegisterView, LoginView, LogoutView, SendOtpView, ValidateOtpView, ChangePasswordView, \
ForgotPasswordView, ListTokensView, KillTokensView, TestAuthView



urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('send-otp/', SendOtpView.as_view(), name='send_otp'),
    path('validate-otp/', ValidateOtpView.as_view(), name='validate_otp'),
    path('change-pass/', ChangePasswordView.as_view(), name='change_pass'),
    path('forgot-pass/', ForgotPasswordView.as_view(), name='forgot_pass'),
    path('list-tokens/', ListTokensView.as_view(), name='list_tokens'),
    path('kill-tokens/', KillTokensView.as_view(), name='kill_tokens'),
    path('test-auth/', TestAuthView.as_view(), name='test_auth'),
]
