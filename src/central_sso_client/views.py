from __future__ import annotations
import secrets
import requests
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods
from .conf import get_sso_settings
from .discovery import get_openid_config
from .jwks import validate_jwt
from .pkce import generate_code_verifier, code_challenge_s256
from .state import store_auth_flow, pop_and_validate_flow
import logging
logger = logging.getLogger(__name__)

@require_http_methods(["GET"])
def login(request: HttpRequest) -> HttpResponse:
    return redirect("https://accounts.saveetha.in")
    print("saveetha portal")
    try:
        sso = get_sso_settings()
        cfg = get_openid_config()
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        verifier = generate_code_verifier()
        challenge = code_challenge_s256(verifier)
        next_url = request.GET.get("next", "/")

        store_auth_flow(request, state=state, nonce=nonce, code_verifier=verifier, next_url=next_url)

        params = {
            "response_type": "code",
            "client_id": sso.CLIENT_ID,
            "redirect_uri": sso.REDIRECT_URI,
            "scope": sso.SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
        print("saveetha:REDIRECT_URI:"+sso.REDIRECT_URI)

        return redirect(f"{cfg['authorization_endpoint']}?{query}")

    except Exception:
        # This logs the full traceback (critical for finding the real reason)
        logger.exception("Error during login view")
        return HttpResponse(
            "An error occurred during login. Please try again later.",
            status=500,
            content_type="text/plain",
        )


@require_http_methods(["GET"])
def callback(request: HttpRequest) -> HttpResponse:
    sso = get_sso_settings()
    cfg = get_openid_config()
    code = request.GET.get("code")
    state = request.GET.get("state")
    if not code or not state:
        return redirect("/sso/login/")
    flow = pop_and_validate_flow(request, state)

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": sso.REDIRECT_URI,
        "client_id": sso.CLIENT_ID,
        "code_verifier": flow["code_verifier"],
    }
    headers = {}
    auth = None
    if sso.CLIENT_SECRET:
        auth = (sso.CLIENT_ID, sso.CLIENT_SECRET)
    resp = requests.post(cfg["token_endpoint"], data=data, headers=headers, auth=auth, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()

    id_token = tokens.get("id_token")
    claims = validate_jwt(id_token, issuer=cfg["issuer"], audience=sso.CLIENT_ID) if id_token else {}

    user_data = {
        "sub": claims.get("sub"),
        "email": claims.get("email"),
        "preferred_username": claims.get("preferred_username"),
        "name": claims.get("name"),
    }
    if not user_data.get("sub") and tokens.get("access_token"):
        info = requests.get(
            cfg["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=5,
        )
        if info.status_code == 200:
            user_data.update(info.json())

    request.session[sso.SESSION_KEY] = {
        "user": user_data,
        "tokens": tokens,
    }
    return redirect(flow.get("next") or "/")


def logout(request: HttpRequest) -> HttpResponse:
    sso = get_sso_settings()
    request.session.pop(sso.SESSION_KEY, None)
    cfg = get_openid_config()
    return redirect(cfg.get("end_session_endpoint", "/"))
