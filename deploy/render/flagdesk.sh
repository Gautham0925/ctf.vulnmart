#!/bin/sh
set -e
export PORT="${PORT:-8000}"
python scripts/db_bootstrap.py
alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --workers "${WEB_CONCURRENCY:-1}" --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 15
