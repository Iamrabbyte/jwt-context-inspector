# JWT Context Inspector

[![Tests](https://github.com/Iamrabbyte/jwt-context-inspector/actions/workflows/tests.yml/badge.svg)](https://github.com/Iamrabbyte/jwt-context-inspector/actions/workflows/tests.yml)

A small defensive CLI tool for inspecting JWT header and payload metadata during authorized security testing.

The tool decodes JWT contents and performs lightweight security-oriented review of common authentication and authorization context.

It is intended for inspection, debugging, documentation, and authorized security review.

## Features

JWT Context Inspector currently reviews:

### Payload Claims

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

### Header Security Context

The tool also reviews common JWT header fields, including:

- `alg`
- `kid`
- `jku`
- `x5u`

Security-oriented warnings are produced when potentially sensitive or risky metadata is observed.

Examples include:

- unsigned tokens using `alg: none`
- missing issuer or audience claims
- missing common tenant-binding claims
- expired tokens
- tokens that are not valid yet
- unusually long token lifetimes
- future `iat` values
- `kid`-based key selection
- remote JWK references through `jku`
- remote certificate references through `x5u`

These warnings provide review context only.

They do not prove that a vulnerability exists.

## Usage

Run the tool with a JWT:

    python jwt_inspector.py <JWT>

You can also provide a token through standard input:

    echo "<JWT>" | python jwt_inspector.py

## Example

The following token is synthetic and intentionally uses `alg: none` so the security review behavior can be demonstrated.

    python jwt_inspector.py eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMtdXNlciIsImF1ZCI6ImRlbW8tYXBpIiwidGVuYW50X2lkIjoibGFiLXRlbmFudCIsImV4cCI6MTg5MzQ1NjAwMH0.

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

    === Security Review ===
    [!] Algorithm is 'none'. Token is unsigned.
    [+] Token has not expired.
    [!] No issuer ('iss') claim observed.

    Note: decoding and reviewing JWT metadata does NOT verify its signature, authenticity, trust, or authorization scope.

The exact remaining lifetime value depends on the current system time.

## Why This Exists

During API and multi-tenant security assessments, reviewing JWT context often requires more than simply decoding the token.

Useful questions include:

- Which algorithm is declared?
- Is the token unsigned?
- Is an issuer defined?
- Is an audience defined?
- Is the token expired?
- Is it valid yet?
- How long is its declared lifetime?
- Does it contain tenant-binding context?
- Does the header reference external key material?
- Does key selection depend on `kid`?

JWT Context Inspector provides a lightweight command-line view of these signals without requiring a browser-based decoder.

## Security Review Scope

The tool performs static metadata analysis only.

It can identify conditions that deserve manual review, but it does not determine whether the receiving application is vulnerable.

For example, the presence of:

- `kid`
- `jku`
- `x5u`
- a missing audience
- a missing tenant claim

is not automatically a security vulnerability.

Security impact depends on how the receiving application validates and uses those values.

## Security Note

Decoding a JWT is not the same as verifying it.

This tool does not confirm:

- whether the JWT signature is valid
- whether the issuer is trusted
- whether the signing key is legitimate
- whether the token is currently authorized
- whether claims are enforced by the receiving application
- whether tenant isolation is correctly implemented

A decoded token should not be treated as trusted without cryptographic verification and server-side authorization checks.

## Scope

This project intentionally does not include offensive token-manipulation features.

It does not perform:

- token forgery
- secret cracking
- signature bypass attempts
- algorithm-confusion exploitation
- brute force
- automated authentication attacks
- remote exploitation

The project is focused on inspection, defensive review, and security context analysis.

## Requirements

- Python 3.9 or later
- No third-party dependencies

## Running Locally

Clone the repository:

    git clone https://github.com/Iamrabbyte/jwt-context-inspector.git
    cd jwt-context-inspector

Run the tool:

    python jwt_inspector.py <JWT>

## Tests

The project includes unit tests for decoding behavior and security-review logic.

Run the complete test suite with:

    python -m unittest discover -s tests -v

Current test coverage includes:

- Base64URL decoding
- JSON payload decoding
- malformed segment rejection
- non-object JSON rejection
- `alg: none` detection
- normal algorithm reporting
- `kid`, `jku`, and `x5u` header review
- expired token detection
- future `nbf` detection
- unusually long token lifetime detection
- missing issuer, audience, and tenant-binding warnings

Current test result:

    Ran 11 tests

    OK

## Continuous Integration

The test suite runs automatically through GitHub Actions on pushes and pull requests.

The workflow currently validates the project against multiple Python versions.

## License

This project is released under the MIT License.

See [LICENSE](LICENSE).

## Responsible Use

Use this utility only with tokens and systems you own or are explicitly authorized to assess.

Do not publish real authentication tokens, credentials, private user data, or other sensitive material in issues, commits, screenshots, or reports.

## Author

Iamrabbyte

Security research focused on web applications, APIs, authentication, authorization, and evidence-driven validation.
