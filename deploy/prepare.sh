#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "copy .env.example to .env and fill it in first"; exit 1; }
set -a; . ./.env; set +a
SERVICE_TOKEN_SHA256=$(printf %s "$SERVICE_TOKEN" | sha256sum | cut -d' ' -f1)
grep -q '^SERVICE_TOKEN_SHA256=' .env && sed -i "s/^SERVICE_TOKEN_SHA256=.*/SERVICE_TOKEN_SHA256=$SERVICE_TOKEN_SHA256/" .env || echo "SERVICE_TOKEN_SHA256=$SERVICE_TOKEN_SHA256" >> .env
python3 ../scripts/render_pgbouncer.py
echo "ready: docker compose --env-file .env up -d --build"
