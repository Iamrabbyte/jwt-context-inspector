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


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_json_segment(segment: str) -> dict:
    try:
        raw = b64url_decode(segment)
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Could not decode JWT segment: {exc}") from exc


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

    print(
        "\nNote: decoding a JWT does NOT verify its signature, authenticity, "
        "or authorization scope."
    )


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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Decode and inspect JWT header/payload claims without verifying "
            "the token signature."
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
