#!/bin/sh
# Create deploy/.env from .env.example with freshly generated secrets.
# Usage: ./scripts/init-env.sh [domain]
set -eu
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env already exists - not overwriting it." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
domain="${1:-}"
if [ -z "$domain" ]; then
  printf "Domain for Provenza (e.g. provenza.example.com, or localhost): "
  read -r domain
fi
[ -n "$domain" ] || { echo "a domain is required" >&2; exit 1; }

secret_key=$(openssl rand -base64 48 | tr -d '\n')
fernet_key=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')
pg_pass=$(openssl rand -hex 24)
redis_pass=$(openssl rand -hex 24)

umask 077
sed -e "s|^PROVENZA_DOMAIN=.*|PROVENZA_DOMAIN=${domain}|" \
    -e "s|^SECRET_KEY=.*|SECRET_KEY=${secret_key}|" \
    -e "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${fernet_key}|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg_pass}|" \
    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${redis_pass}|" \
    -e "s|^SMTP_FROM=.*|SMTP_FROM=provenza@${domain}|" \
    .env.example > .env
chmod 600 .env
echo "Created deploy/.env (mode 600) for ${domain}."
echo "Back up deploy/.env somewhere safe: ENCRYPTION_KEY cannot be recovered."
