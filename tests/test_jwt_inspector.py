import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone

from jwt_inspector import (
    b64url_decode,
    decode_json_segment,
    review_algorithm,
    review_expiration,
    review_header_fields,
    review_identity_binding,
    review_not_before,
    review_token_lifetime,
)


class TestJWTInspector(unittest.TestCase):
    def capture_output(self, func, *args):
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            func(*args)

        return buffer.getvalue()

    def test_base64url_decode(self):
        decoded = b64url_decode("eyJzdWIiOiJ0ZXN0In0")
        self.assertEqual(decoded.decode("utf-8"), '{"sub":"test"}')

    def test_decode_json_segment(self):
        result = decode_json_segment(
            "eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9"
        )

        self.assertEqual(result["sub"], "synthetic-user")

    def test_decode_json_segment_rejects_invalid_data(self):
        with self.assertRaises(ValueError):
            decode_json_segment("%%%invalid%%%")

    def test_decode_json_segment_rejects_non_object_json(self):
        with self.assertRaises(ValueError):
            decode_json_segment("WyJub3QiLCJhbiIsIm9iamVjdCJd")

    def test_alg_none_warning(self):
        output = self.capture_output(
            review_algorithm,
            {"alg": "none"},
        )

        self.assertIn(
            "Algorithm is 'none'. Token is unsigned.",
            output,
        )

    def test_normal_algorithm_is_reported(self):
        output = self.capture_output(
            review_algorithm,
            {"alg": "RS256"},
        )

        self.assertIn(
            "Declared algorithm: RS256",
            output,
        )

    def test_risky_header_fields_are_reported(self):
        header = {
            "alg": "RS256",
            "kid": "example-key",
            "jku": "https://example.invalid/jwks.json",
            "x5u": "https://example.invalid/cert.pem",
        }

        output = self.capture_output(
            review_header_fields,
            header,
        )

        self.assertIn("'kid' header is present", output)
        self.assertIn("'jku' header is present", output)
        self.assertIn("'x5u' header is present", output)

    def test_expired_token_warning(self):
        now_ts = datetime.now(
            tz=timezone.utc
        ).timestamp()

        payload = {
            "exp": now_ts - 60,
        }

        output = self.capture_output(
            review_expiration,
            payload,
            now_ts,
        )

        self.assertIn("Token is expired", output)

    def test_future_nbf_warning(self):
        now_ts = datetime.now(
            tz=timezone.utc
        ).timestamp()

        payload = {
            "nbf": now_ts + 3600,
        }

        output = self.capture_output(
            review_not_before,
            payload,
            now_ts,
        )

        self.assertIn(
            "Token is not valid yet",
            output,
        )

    def test_long_token_lifetime_warning(self):
        payload = {
            "iat": 1_700_000_000,
            "exp": 1_700_000_000 + (60 * 60 * 24 * 90),
        }

        output = self.capture_output(
            review_token_lifetime,
            payload,
        )

        self.assertIn(
            "Token lifetime is unusually long",
            output,
        )

    def test_missing_identity_binding_warnings(self):
        payload = {
            "sub": "synthetic-user",
        }

        output = self.capture_output(
            review_identity_binding,
            payload,
        )

        self.assertIn(
            "No issuer ('iss') claim observed",
            output,
        )

        self.assertIn(
            "No audience ('aud') claim observed",
            output,
        )

        self.assertIn(
            "No common tenant-binding claim observed",
            output,
        )


if __name__ == "__main__":
    unittest.main()
