from django.urls import path, include
from account.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('sregister/', SellerRegistrationView.as_view(), name='register'),
    path('slogin/', SellerLoginView.as_view(), name='login'),
    path('sprofile/', SellerProfileView.as_view(), name='profile'),
    path('schangepassword/', SellerChangePasswordView.as_view(), name='changepassword'),
    path('ssend-reset-password-email/', SellerSendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('sreset-password/<uid>/<token>/', SellerPasswordResetView.as_view(), name='reset-password')
]