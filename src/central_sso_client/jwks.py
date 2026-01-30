from __future__ import annotations
import json
import time
import requests
import jwt
from jwt import PyJWKClient
from django.core.cache import cache
from .conf import get_sso_settings
from .discovery import get_openid_config


JWKS_CACHE_KEY = "central_sso_jwks"


def get_jwks() -> dict:
    cached = cache.get(JWKS_CACHE_KEY)
    if cached:
        return cached
    cfg = get_openid_config()
    resp = requests.get(cfg["jwks_uri"], timeout=5)
    resp.raise_for_status()
    data = resp.json()
    sso = get_sso_settings()
    cache.set(JWKS_CACHE_KEY, data, timeout=sso.JWKS_CACHE_SECONDS)
    return data


def validate_jwt(token: str, issuer: str, audience: str) -> dict:
    cfg = get_openid_config()
    jwks_client = PyJWKClient(cfg["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=audience, issuer=issuer)
