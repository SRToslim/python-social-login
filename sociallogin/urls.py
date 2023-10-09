from django.urls import path

from .views import *

urlpatterns = [
    path('auth/google/', google_login, name='google_login'),
    path('auth/google/callback/', google_callback, name='google_callback'),
    path('auth/facebook/', facebook_login, name='facebook_login'),
    path('auth/facebook/callback/', facebook_callback, name='facebook_callback'),
    path('auth/github/', github_login, name='github_login'),
    path('auth/github/callback/', github_callback, name='github_callback'),
]