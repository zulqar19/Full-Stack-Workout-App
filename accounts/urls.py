from django.urls import path
from . views import UserRegistrationView , UserLoginView , UserProfileView, UserChangePasswordView, SendPasswordResetEmailView, ResetPasswordView, UserLogoutView

urlpatterns = [
    path('register/', UserRegistrationView , name='register'),
    path('login/', UserLoginView , name='login'),
    path('profile/', UserProfileView , name='profile'),
    path('changepassword/', UserChangePasswordView , name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView , name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', ResetPasswordView , name='reset-password'),
    path('logout/', UserLogoutView , name='logout'),
]
