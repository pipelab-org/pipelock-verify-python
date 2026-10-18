# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `pipelock-verify`, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report via **[GitHub Security Advisories](https://github.com/pipelab-org/pipelock-verify-python/security/advisories/new)**.

Include:

- Description of the vulnerability
- Steps to reproduce (minimal receipt JSON or JSONL preferred)
- Impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 1 week
- **Fix and disclosure:** coordinated with reporter, typically within 30 days

## Scope

In scope:

- Signature forgery or verification bypass
- Canonicalization drift that causes a Go-valid receipt to verify as invalid in Python, or a Go-invalid receipt to verify as valid in Python
- Chain linkage bypass (accepting a chain with a broken `chain_prev_hash`)
- Trust anchor bypass (accepting a receipt signed by a different key when `public_key_hex` was pinned)
- Crashes or hangs on malformed input that could be used for denial of service

Out of scope:

- Vulnerabilities in the underlying `cryptography` library (report to that project)
- Issues in the Go reference implementation (report via [Pipelock Security Advisories](https://github.com/pipelab-org/pipelock/security/advisories/new))

## Supported Versions

Only the latest minor release receives security fixes. Earlier versions do not receive backports.

## Cryptographic Dependencies

`pipelock-verify` delegates all Ed25519 primitives to [`cryptography`](https://cryptography.io). Signature verification is constant-time by virtue of that library. This package does not reimplement cryptography.
