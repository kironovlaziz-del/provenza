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
- Bypassing a policy decision: an agent action, gateway call or egress
  connection that should have been denied or held for approval but was not.

Out of scope:

- Issues that require physical access to the server.
- Denial of service via resource exhaustion on a single-user instance.
- Vulnerabilities in third-party dependencies without a demonstrated
  exploit path in this project (please report those upstream).

## Hardening checklist for operators

If you run Provenza in production:

- Set `ENVIRONMENT=production` — insecure defaults are rejected at startup.
- Require two-factor sign-in at least for admins and approvers
  (Users → Two-factor sign-in policy); each person sets it up under My profile.
- Set a strong `SECRET_KEY` (48+ random bytes) and `ENCRYPTION_KEY` (Fernet).
- Bind Postgres and Redis to `127.0.0.1` (the default in `docker-compose.yml`).
- Put the app behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik).
- Back up the Postgres volume regularly.
- Rotate `ENCRYPTION_KEY` using `scripts/rotate_encryption_key.py` if it
  ever leaks.
- Allow SSH with keys only (`PasswordAuthentication no`), and expose only
  ports 80 and 443; Postgres, Redis, the API (8000) and the web UI (3000)
  listen on localhost.
- The app sends its own security headers (CSP, framing, HSTS in production),
  so any reverse proxy works. With a bare nginx in front, also limit request
  rates there - the app's own limits count per account and per key, nginx's
  per client address:

  ```nginx
  # http { ... }
  limit_req_zone $binary_remote_addr zone=pvz_api:10m rate=30r/s;
  limit_req_zone $binary_remote_addr zone=pvz_auth:10m rate=5r/m;

  # server { ... }
  client_max_body_size 20m;
  location = /api/v1/auth/login { limit_req zone=pvz_auth burst=5 nodelay; proxy_pass http://127.0.0.1:8000; }
  location /api/ { limit_req zone=pvz_api burst=60 nodelay; proxy_pass http://127.0.0.1:8000; }
  ```

  Keep the existing `proxy_set_header` lines in each location.
