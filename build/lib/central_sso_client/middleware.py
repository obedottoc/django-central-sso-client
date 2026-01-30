from __future__ import annotations
from dataclasses import dataclass
from django.http import HttpRequest
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from .conf import get_sso_settings


@dataclass
class SSOUser:
    sub: str
    email: str | None
    preferred_username: str | None
    name: str | None

    @property
    def is_authenticated(self) -> bool:
        return True


class SSORequiredMiddleware(MiddlewareMixin):
    exempt_prefixes = ("/sso/", "/admin/", "/static/")

    def process_request(self, request: HttpRequest):
        path = request.path
        if path.startswith(self.exempt_prefixes):
            return None
        sso = get_sso_settings()
        sess = request.session.get(sso.SESSION_KEY, {})
        if sess.get("user"):
            return None
        return redirect(f"/sso/login/?next={path}")


class SSOUserMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        sso = get_sso_settings()
        sess = request.session.get(sso.SESSION_KEY, {})
        user = sess.get("user")
        if user:
            request.user = SSOUser(
                sub=user.get("sub"),
                email=user.get("email"),
                preferred_username=user.get("preferred_username"),
                name=user.get("name"),
            )
        return None
