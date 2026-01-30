import unittest
import django
from django.conf import settings
from django.test import RequestFactory
from django.contrib.sessions.middleware import SessionMiddleware
from central_sso_client.state import store_auth_flow, pop_and_validate_flow


if not settings.configured:
    settings.configure(
        SECRET_KEY="test",
        MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware"],
        INSTALLED_APPS=["django.contrib.sessions"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
    )
    django.setup()


class StateTests(unittest.TestCase):
    def test_state_validation(self):
        rf = RequestFactory()
        req = rf.get("/")
        SessionMiddleware(lambda r: None).process_request(req)
        req.session.save()
        store_auth_flow(req, state="s1", nonce="n1", code_verifier="v1", next_url="/x")
        flow = pop_and_validate_flow(req, state="s1")
        self.assertEqual(flow["nonce"], "n1")


if __name__ == "__main__":
    unittest.main()
