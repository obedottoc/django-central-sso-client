import unittest
from central_sso_client.pkce import generate_code_verifier, code_challenge_s256


class PKCETests(unittest.TestCase):
    def test_pkce_roundtrip(self):
        verifier = generate_code_verifier()
        challenge = code_challenge_s256(verifier)
        self.assertTrue(isinstance(verifier, str) and len(verifier) >= 43)
        self.assertTrue(isinstance(challenge, str) and len(challenge) > 10)
