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


@require_http_methods(["GET"])
def login(request: HttpRequest) -> HttpResponse:
    # return HttpResponse("An error occurred during login1. Please try again later.", status=500)
    res = "Start"
    try:
        sso = get_sso_settings()
        cfg = get_openid_config()
        state = secrets.token_urlsafe(16)
        res += "A"
        nonce = secrets.token_urlsafe(16)
        verifier = generate_code_verifier()
        challenge = code_challenge_s256(verifier)
        next_url = request.GET.get("next", "/")
        res += "B"
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
        res += "C"
        query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    except Exception as e:
        print(f"Error during login: {e}")    
        return HttpResponse("An error occurred during login. Please try again later."+res, status=500)
    return redirect(f"{cfg['authorization_endpoint']}?{query}")


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

    request.session[sso.SESSION_KEY] = {
        "user": {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "preferred_username": claims.get("preferred_username"),
            "name": claims.get("name"),
        },
        "tokens": tokens,
    }
    return redirect(flow.get("next") or "/")


def logout(request: HttpRequest) -> HttpResponse:
    sso = get_sso_settings()
    request.session.pop(sso.SESSION_KEY, None)
    cfg = get_openid_config()
    return redirect(cfg.get("end_session_endpoint", "/"))
