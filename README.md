# JWT Context Inspector

A small defensive CLI tool for inspecting JWT header and payload claims during authorized security testing.

The tool decodes JWT contents and highlights security-relevant context such as issuer, subject, audience, expiration, and tenant-related claims.

It is intended for inspection, debugging, documentation, and authorized security review.

## Features

The tool currently reviews the following claims:

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

It also provides simple context warnings when common claims are missing.

## Usage

Run the tool with a JWT:

    python jwt_inspector.py <JWT>

You can also provide a token through standard input:

    echo "<JWT>" | python jwt_inspector.py

## Example

    python jwt_inspector.py eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMtdXNlciIsImF1ZCI6ImRlbW8tYXBpIiwidGVuYW50X2lkIjoibGFiLXRlbmFudCIsImV4cCI6MTg5MzQ1NjAwMH0.

The token above is synthetic and included only for demonstration.

## Example Output

    === Header ===
    {
      "alg": "none",
      "typ": "JWT"
    }

    === Payload ===
    {
      "sub": "synthetic-user",
      "aud": "demo-api",
      "tenant_id": "lab-tenant",
      "exp": 1893456000
    }

    === Claim Review ===
    [-] iss: not present
    [+] sub: synthetic-user
    [+] aud: demo-api
    [+] exp: 1893456000 (2030-01-01T00:00:00+00:00)
    [-] iat: not present
    [-] nbf: not present
    [-] jti: not present
    [+] tenant_id: lab-tenant
    [-] tenantId: not present
    [-] tid: not present

    === Context Notes ===
    [+] Audience claim is present.
    [+] Tenant-related claim is present.
    [+] Expiration claim is present.

    Note: decoding a JWT does NOT verify its signature, authenticity, or authorization scope.

## Why This Exists

During API and multi-tenant security assessments, it is often useful to quickly inspect whether a JWT contains claims that bind it to:

- a specific issuer;
- an intended audience;
- a tenant context;
- a subject;
- a defined lifetime.

This tool provides a lightweight command-line view of that information without requiring a browser-based decoder.

## Security Note

Decoding a JWT is not the same as verifying it.

This tool does not confirm:

- whether the signature is valid;
- whether the issuer is trusted;
- whether the token is currently authorized;
- whether the claims are actually enforced by the receiving application.

A decoded token should not be treated as trusted without proper cryptographic verification and server-side authorization checks.

## Scope

This project intentionally does not include offensive token-manipulation features.

It does not perform:

- token forgery;
- secret cracking;
- signature bypass attempts;
- algorithm-confusion exploitation;
- brute force;
- automated authentication attacks.

The project is focused on inspection and analysis.

## Requirements

- Python 3.9 or later
- No third-party dependencies

## Running Locally

Clone the repository:

    git clone https://github.com/Iamrabbyte/jwt-context-inspector.git
    cd jwt-context-inspector

Run the tool:

    python jwt_inspector.py <JWT>

## Responsible Use

Use this utility only with tokens and systems you own or are explicitly authorized to assess.

Do not publish real authentication tokens, credentials, private user data, or other sensitive material in issues, commits, screenshots, or reports.

## Author

Iamrabbyte

Security research focused on web applications, APIs, authentication, authorization, and evidence-driven validation.
