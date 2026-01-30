from __future__ import annotations
from typing import Dict
from django.http import HttpRequest
from .conf import get_sso_settings


SESSION_FLOW_KEY = "_sso_flow"


def store_auth_flow(request: HttpRequest, state: str, nonce: str, code_verifier: str, next_url: str) -> None:
    request.session[SESSION_FLOW_KEY] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "next": next_url,
    }


def pop_and_validate_flow(request: HttpRequest, state: str) -> Dict[str, str]:
    flow = request.session.pop(SESSION_FLOW_KEY, {})
    if flow.get("state") != state:
        raise ValueError("invalid_state")
    return flow
