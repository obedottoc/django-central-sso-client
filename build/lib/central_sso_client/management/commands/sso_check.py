from __future__ import annotations
from django.core.management.base import BaseCommand
from central_sso_client.discovery import get_openid_config
from central_sso_client.jwks import get_jwks


class Command(BaseCommand):
    help = "Check connectivity to auth server discovery + JWKS."

    def handle(self, *args, **options):
        cfg = get_openid_config()
        jwks = get_jwks()
        self.stdout.write(self.style.SUCCESS("Discovery OK"))
        self.stdout.write(f"issuer: {cfg.get('issuer')}")
        self.stdout.write(f"jwks keys: {len(jwks.get('keys', []))}")
