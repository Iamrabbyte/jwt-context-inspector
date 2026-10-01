import unittest

from jwt_inspector import b64url_decode, decode_json_segment


class TestJWTInspector(unittest.TestCase):
    def test_base64url_decode(self):
        decoded = b64url_decode("eyJzdWIiOiJ0ZXN0In0")
        self.assertEqual(decoded.decode("utf-8"), '{"sub":"test"}')

    def test_decode_json_segment(self):
        result = decode_json_segment("eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9")
        self.assertEqual(result["sub"], "synthetic-user")

    def test_decode_json_segment_rejects_invalid_data(self):
        with self.assertRaises(ValueError):
            decode_json_segment("%%%invalid%%%")

    def test_decode_json_segment_handles_claims(self):
        result = decode_json_segment(
            "eyJhdWQiOiJkZW1vLWFwaSIsInRlbmFudF9pZCI6ImxhYi10ZW5hbnQifQ"
        )

        self.assertEqual(result["aud"], "demo-api")
        self.assertEqual(result["tenant_id"], "lab-tenant")


if __name__ == "__main__":
    unittest.main()
