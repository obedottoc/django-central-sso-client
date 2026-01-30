from __future__ import annotations
import json
import requests
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Register this client with the auth server using a registration key."

    def add_arguments(self, parser):
        parser.add_argument("--auth-server", required=True)
        parser.add_argument("--registration-key", required=True)
        parser.add_argument("--slug", required=True)
        parser.add_argument("--display-name", required=False)
        parser.add_argument("--redirect-uri", required=True)
        parser.add_argument("--post-logout-redirect-uri", required=False)
        parser.add_argument("--client-type", choices=["confidential", "public"], default="confidential")

    def handle(self, *args, **opts):
        url = opts["auth_server"].rstrip("/") + "/api/v1/clients/register/"
        payload = {
            "registration_key": opts["registration_key"],
            "slug": opts["slug"],
            "display_name": opts.get("display_name") or opts["slug"],
            "redirect_uris": [opts["redirect_uri"]],
            "post_logout_redirect_uris": [opts["post_logout_redirect_uri"]] if opts.get("post_logout_redirect_uri") else [],
            "client_type": opts["client_type"],
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code not in (200, 201):
            raise SystemExit(f"Registration failed: {resp.status_code} {resp.text}")
        data = resp.json()
        self.stdout.write(self.style.SUCCESS("Registered client"))
        self.stdout.write(json.dumps(data, indent=2))
        self.stdout.write("\nSuggested CENTRAL_SSO settings:")
        self.stdout.write(f'  AUTH_SERVER_URL="{opts["auth_server"].rstrip("/")}"')
        self.stdout.write(f'  CLIENT_ID="{data["client_id"]}"')
        if data.get("client_secret"):
            self.stdout.write(f'  CLIENT_SECRET="{data["client_secret"]}"')
