from __future__ import annotations
from typing import Optional, Tuple
from .conf import get_sso_settings
from .discovery import get_openid_config
from .jwks import validate_jwt
from .middleware import SSOUser


class BearerJWTAuthentication:
    """DRF Authentication class validating Bearer JWT via JWKS."""

    def authenticate(self, request) -> Optional[Tuple[object, dict]]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        cfg = get_openid_config()
        sso = get_sso_settings()
        claims = validate_jwt(token, issuer=cfg["issuer"], audience=sso.CLIENT_ID)
        user = SSOUser(
            sub=claims.get("sub", ""),
            email=claims.get("email"),
            preferred_username=claims.get("preferred_username"),
            name=claims.get("name"),
        )
        return (user, claims)
