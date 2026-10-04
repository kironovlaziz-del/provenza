# Security Policy

## Supported versions

The `main` branch receives security fixes. Tagged releases are supported
for 6 months after their release date.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use one of these private channels:

1. GitHub's private vulnerability reporting:
   https://github.com/kironovlaziz-del/provenza/security/advisories/new
2. Email: `frulenhurram@gmail.com`

Include in your report:

- A description of the issue.
- Steps to reproduce, or a proof-of-concept.
- The affected component (backend, frontend, container, ...).
- Any suggested mitigation.

You will receive an acknowledgment within **72 hours**. We aim to ship a
fix or mitigation within **30 days** for confirmed issues. We will credit
you in the advisory unless you prefer to stay anonymous.

## Scope

In scope:

- Authentication and authorization bypasses.
- SQL injection, XSS, CSRF, SSRF.
- Credential leakage (API keys, tokens, passwords).
- Container escape.
- Prompt Firewall evasion that leaks raw PII to a provider.

Out of scope:

- Issues that require physical access to the server.
- Denial of service via resource exhaustion on a single-user instance.
- Vulnerabilities in third-party dependencies without a demonstrated
  exploit path in this project (please report those upstream).

## Hardening checklist for operators

If you run Provenza in production:

- Set `ENVIRONMENT=production` — insecure defaults are rejected at startup.
- Set a strong `SECRET_KEY` (48+ random bytes) and `ENCRYPTION_KEY` (Fernet).
- Bind Postgres and Redis to `127.0.0.1` (the default in `docker-compose.yml`).
- Put the app behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik).
- Back up the Postgres volume regularly.
- Rotate `ENCRYPTION_KEY` using `scripts/rotate_encryption_key.py` if it
  ever leaks.
- Enable `PROMPT_FIREWALL_NER_ENABLED` for stronger PII detection.
