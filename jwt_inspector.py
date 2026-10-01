#!/usr/bin/env python3

import argparse
import base64
import json
import sys
from datetime import datetime, timezone


IMPORTANT_CLAIMS = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "tenant_id",
    "tenantId",
    "tid",
]

RISKY_HEADER_FIELDS = [
    "kid",
    "jku",
    "x5u",
]


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_json_segment(segment: str) -> dict:
    try:
        raw = b64url_decode(segment)
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Could not decode JWT segment: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Decoded JWT segment is not a JSON object.")

    return data


def format_timestamp(value):
    if not isinstance(value, (int, float)):
        return value

    try:
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return f"{value} ({dt.isoformat()})"
    except Exception:
        return value


def print_section(title: str, data: dict):
    print(f"\n=== {title} ===")
    print(json.dumps(data, indent=2, ensure_ascii=False))


def inspect_claims(payload: dict):
    print("\n=== Claim Review ===")

    for claim in IMPORTANT_CLAIMS:
        if claim in payload:
            value = payload[claim]

            if claim in {"exp", "iat", "nbf"}:
                value = format_timestamp(value)

            print(f"[+] {claim}: {value}")
        else:
            print(f"[-] {claim}: not present")


def print_context_notes(payload: dict):
    print("\n=== Context Notes ===")

    audience_present = "aud" in payload
    tenant_claims = ["tenant_id", "tenantId", "tid"]
    tenant_present = any(claim in payload for claim in tenant_claims)

    if audience_present:
        print("[+] Audience claim is present.")
    else:
        print("[!] No audience claim observed.")

    if tenant_present:
        print("[+] Tenant-related claim is present.")
    else:
        print("[!] No common tenant-context claim observed.")

    if "exp" in payload:
        print("[+] Expiration claim is present.")
    else:
        print("[!] No expiration claim observed.")


def review_algorithm(header: dict):
    alg = header.get("alg")

    if alg is None:
        print("[!] No 'alg' header observed.")
        return

    if not isinstance(alg, str):
        print("[!] 'alg' header is not a string.")
        return

    normalized = alg.strip().lower()

    if normalized == "none":
        print("[!] Algorithm is 'none'. Token is unsigned.")
    else:
        print(f"[+] Declared algorithm: {alg}")


def review_header_fields(header: dict):
    for field in RISKY_HEADER_FIELDS:
        if field not in header:
            continue

        value = header[field]

        if field == "kid":
            print(
                "[!] 'kid' header is present. Ensure key selection is strictly "
                "controlled and does not allow unsafe lookup behavior."
            )

        elif field == "jku":
            print(
                "[!] 'jku' header is present. Verify that remote key-set URLs "
                "are restricted to trusted locations."
            )

        elif field == "x5u":
            print(
                "[!] 'x5u' header is present. Verify that certificate URLs "
                "are restricted to trusted locations."
            )

        if value in ("", None):
            print(f"[!] '{field}' is present but empty.")


def review_expiration(payload: dict, now_ts: float):
    exp = payload.get("exp")

    if exp is None:
        print("[!] Token has no expiration claim.")
        return

    if not isinstance(exp, (int, float)):
        print("[!] 'exp' claim is not numeric.")
        return

    if exp < now_ts:
        delta = int(now_ts - exp)
        print(f"[!] Token is expired by approximately {delta} seconds.")
    else:
        delta = int(exp - now_ts)
        print(f"[+] Token has not expired. Approximately {delta} seconds remain.")


def review_not_before(payload: dict, now_ts: float):
    nbf = payload.get("nbf")

    if nbf is None:
        return

    if not isinstance(nbf, (int, float)):
        print("[!] 'nbf' claim is not numeric.")
        return

    if nbf > now_ts:
        delta = int(nbf - now_ts)
        print(
            f"[!] Token is not valid yet. 'nbf' is approximately "
            f"{delta} seconds in the future."
        )
    else:
        print("[+] Token is past its declared 'nbf' time.")


def review_issued_at(payload: dict, now_ts: float):
    iat = payload.get("iat")

    if iat is None:
        return

    if not isinstance(iat, (int, float)):
        print("[!] 'iat' claim is not numeric.")
        return

    if iat > now_ts + 300:
        delta = int(iat - now_ts)
        print(
            f"[!] 'iat' is approximately {delta} seconds in the future. "
            "Check clock synchronization or token issuance logic."
        )


def review_token_lifetime(payload: dict):
    iat = payload.get("iat")
    exp = payload.get("exp")

    if not isinstance(iat, (int, float)):
        return

    if not isinstance(exp, (int, float)):
        return

    lifetime = exp - iat

    if lifetime < 0:
        print("[!] 'exp' occurs before 'iat'.")
        return

    hours = lifetime / 3600
    days = hours / 24

    if lifetime > 60 * 60 * 24 * 30:
        print(
            f"[!] Token lifetime is unusually long: approximately "
            f"{days:.1f} days."
        )
    elif lifetime > 60 * 60 * 24:
        print(
            f"[!] Token lifetime is relatively long: approximately "
            f"{days:.1f} days."
        )
    else:
        print(f"[+] Declared token lifetime: approximately {hours:.1f} hours.")


def review_identity_binding(payload: dict):
    if "iss" not in payload:
        print("[!] No issuer ('iss') claim observed.")

    if "aud" not in payload:
        print("[!] No audience ('aud') claim observed.")

    tenant_claims = ["tenant_id", "tenantId", "tid"]

    if not any(claim in payload for claim in tenant_claims):
        print("[!] No common tenant-binding claim observed.")


def print_security_review(header: dict, payload: dict):
    print("\n=== Security Review ===")

    now_ts = datetime.now(tz=timezone.utc).timestamp()

    review_algorithm(header)
    review_header_fields(header)
    review_expiration(payload, now_ts)
    review_not_before(payload, now_ts)
    review_issued_at(payload, now_ts)
    review_token_lifetime(payload)
    review_identity_binding(payload)


def inspect_jwt(token: str):
    parts = token.strip().split(".")

    if len(parts) != 3:
        raise ValueError("Expected a JWT with three dot-separated segments.")

    header = decode_json_segment(parts[0])
    payload = decode_json_segment(parts[1])

    print_section("Header", header)
    print_section("Payload", payload)
    inspect_claims(payload)
    print_context_notes(payload)
    print_security_review(header, payload)

    print(
        "\nNote: decoding and reviewing JWT metadata does NOT verify its "
        "signature, authenticity, trust, or authorization scope."
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Decode and inspect JWT header/payload claims and report common "
            "security-relevant metadata without verifying the token signature."
        )
    )

    parser.add_argument(
        "token",
        nargs="?",
        help="JWT to inspect. If omitted, the token is read from standard input.",
    )

    args = parser.parse_args()

    token = args.token

    if not token:
        token = sys.stdin.read().strip()

    if not token:
        print("Error: no JWT supplied.", file=sys.stderr)
        sys.exit(1)

    try:
        inspect_jwt(token)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
