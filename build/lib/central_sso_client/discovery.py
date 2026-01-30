from __future__ import annotations
import requests
from django.core.cache import cache
from .conf import get_sso_settings


DISCOVERY_CACHE_KEY = "central_sso_discovery"


def get_openid_config() -> dict:
    cached = cache.get(DISCOVERY_CACHE_KEY)
    if cached:
        return cached
    sso = get_sso_settings()
    url = sso.AUTH_SERVER_URL.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    cache.set(DISCOVERY_CACHE_KEY, data, timeout=sso.JWKS_CACHE_SECONDS)
    return data
