#!/bin/sh
set -e
export PORT="${PORT:-10000}"
sed "s/__PORT__/$PORT/" /etc/nginx/shop.conf.tmpl > /tmp/nginx.conf
MIG="postgresql+psycopg://ctf_migrator:${MIGRATOR_DB_PASSWORD}@${DB_DIRECT_HOST}:5432/${DB_NAME}?sslmode=require&options=-csearch_path%3Dvulnmart"
DATABASE_URL="$MIG" MIGRATOR_DATABASE_URL="postgresql://ctf_migrator:${MIGRATOR_DB_PASSWORD}@${DB_DIRECT_HOST}:5432/${DB_NAME}?sslmode=require" sh -c "alembic upgrade head && python -m app.seed"
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers "${WEB_CONCURRENCY:-1}" --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 15 &
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
