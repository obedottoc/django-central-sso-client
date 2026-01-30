from __future__ import annotations
from dataclasses import dataclass
from django.conf import settings


@dataclass
class SSOSettings:
    AUTH_SERVER_URL: str
    CLIENT_ID: str
    CLIENT_SECRET: str | None
    REDIRECT_URI: str
    SCOPES: str
    JWKS_CACHE_SECONDS: int
    SESSION_KEY: str


def get_sso_settings() -> SSOSettings:
    cfg = getattr(settings, "CENTRAL_SSO", {})
    return SSOSettings(
        AUTH_SERVER_URL=cfg.get("AUTH_SERVER_URL", ""),
        CLIENT_ID=cfg.get("CLIENT_ID", ""),
        CLIENT_SECRET=cfg.get("CLIENT_SECRET"),
        REDIRECT_URI=cfg.get("REDIRECT_URI", ""),
        SCOPES=cfg.get("SCOPES", "openid profile email"),
        JWKS_CACHE_SECONDS=int(cfg.get("JWKS_CACHE_SECONDS", 3600)),
        SESSION_KEY=cfg.get("SESSION_KEY", "central_sso"),
    )
