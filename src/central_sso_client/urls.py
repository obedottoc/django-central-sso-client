from __future__ import annotations
from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login, name="sso_login"),
    path("callback/", views.callback, name="sso_callback"),
    path("logout/", views.logout, name="sso_logout"),
]
