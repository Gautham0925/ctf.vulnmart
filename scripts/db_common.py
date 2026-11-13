import os
import sys
from urllib.parse import quote

import psycopg
from psycopg import sql

SCHEMAS = ("identity", "flagdesk", "vulnmart", "audit")
ROLES = {
    "migrator": ("ctf_migrator", "MIGRATOR_DB_PASSWORD"),
    "flagdesk": ("flagdesk_app", "FLAGDESK_DB_PASSWORD"),
    "vulnmart": ("vulnmart_app", "VULNMART_DB_PASSWORD"),
}


def admin_dsn(dbname=None):
    raw = os.environ.get("ADMIN_DATABASE_URL", "").strip()
    if not raw:
        sys.exit("ADMIN_DATABASE_URL is required (a role that may create roles/schemas)")
    for prefix in ("postgresql+psycopg://", "postgres://"):
        if raw.startswith(prefix):
            raw = "postgresql://" + raw[len(prefix):]
    if dbname:
        base, _, rest = raw.rpartition("/")
        raw = base + "/" + dbname + ("?" + rest.split("?", 1)[1] if "?" in rest else "")
    return raw


def connect(dbname=None):
    return psycopg.connect(admin_dsn(dbname), autocommit=True)


def target_db():
    name = os.environ.get("DB_NAME", "").strip()
    if not name:
        sys.exit("DB_NAME is required")
    return name


def role_url(role_key, host, port, dbname, sslmode=None):
    role, pw_env = ROLES[role_key]
    pw = os.environ[pw_env]
    url = f"postgresql+psycopg://{quote(role)}:{quote(pw, safe='')}@{host}:{port}/{dbname}"
    if sslmode:
        url += f"?sslmode={sslmode}"
    return url
