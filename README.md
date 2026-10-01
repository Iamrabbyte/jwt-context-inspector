# JWT Context Inspector

A small defensive CLI tool for inspecting JWT header and payload claims during authorized security testing.

It decodes JWT contents and highlights security-relevant claims such as:

- `iss`
- `sub`
- `aud`
- `exp`
- `iat`
- `nbf`
- `jti`
- `tenant_id`
- `tenantId`
- `tid`

It also warns when common context claims such as audience, tenant, or expiration are missing.

## Usage

Run the tool with a JWT:

    python jwt_inspector.py <JWT>

You can also pipe a token through standard input:

    echo "<JWT>" | python jwt_inspector.py

## Example

    python jwt_inspector.py eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMtdXNlciIsImF1ZCI6ImRlbW8tYXBpIiwidGVuYW50X2lkIjoibGFiLXRlbmFudCIsImV4cCI6MTg5MzQ1NjAwMH0.

The example token is synthetic and included only for demonstration.

## Security Note

Decoding a JWT does not verify its signature or prove that the token is trusted.

This tool does not perform:

- token forgery
- secret cracking
- signature bypass
- brute force
- authentication attacks

It is intended for inspection, debugging, and authorized security review.

## Requirements

- Python 3.9+
- No third-party dependencies

## Author

Iamrabbyte

Security research focused on web applications, APIs, authentication, authorization, and evidence-driven validation.
