#import django paths

from django.urls import path
from .views import (
    UserCreateView,
    UserLoginView,
    EmailVerifyView,
)

urlpatterns = [
    path('register/', UserCreateView.as_view(), name='user-register'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('verify/', EmailVerifyView.as_view(), name='verify-email'),
]
