# django-central-sso-client

Installable client library for Central Auth SSO.

Configure in your Django settings:

```
CENTRAL_SSO = {
  "AUTH_SERVER_URL": "http://auth.localtest.me:8001",
  "CLIENT_ID": "...",
  "CLIENT_SECRET": "...",
  "REDIRECT_URI": "http://client.localtest.me:8002/sso/callback/",
  "SCOPES": "openid profile email offline_access",
}
```
