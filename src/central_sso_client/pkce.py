from __future__ import annotations
import base64
import hashlib
import secrets


def generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")
