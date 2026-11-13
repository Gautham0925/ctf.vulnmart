import argparse
import os
import sys

from psycopg import sql

sys.path.insert(0, os.path.dirname(__file__))
from db_common import ROLES, SCHEMAS, connect, target_db


def main():
    ap = argparse.ArgumentParser(description="Create schemas, roles and least-privilege grants. Idempotent.")
    ap.add_argument("--create-database", action="store_true", help="create DB_NAME if it does not exist")
    ap.add_argument("--revoke-public-connect", action="store_true", help="REVOKE CONNECT ON DATABASE FROM PUBLIC (only do this on a database that is dedicated to this platform)")
    ap.add_argument("--flagdesk-conn-limit", type=int, default=int(os.environ.get("FLAGDESK_CONN_LIMIT", "80")))
    ap.add_argument("--vulnmart-conn-limit", type=int, default=int(os.environ.get("VULNMART_CONN_LIMIT", "50")))
    ap.add_argument("--vulnmart-statement-timeout", default=os.environ.get("VULNMART_STATEMENT_TIMEOUT", "8s"))
    args = ap.parse_args()
    db = target_db()

    for _, (role, pw_env) in ROLES.items():
        if not os.environ.get(pw_env):
            sys.exit(f"{pw_env} is required")

    with connect() as conn:
        for _, (role, pw_env) in ROLES.items():
            pw = os.environ[pw_env]
            exists = conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone()
            if exists:
                conn.execute(sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(pw)))
            else:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}").format(sql.Identifier(role), sql.Literal(pw)))
        if args.create_database:
            if not conn.execute("select 1 from pg_database where datname=%s", (db,)).fetchone():
                conn.execute(sql.SQL("CREATE DATABASE {} OWNER ctf_migrator").format(sql.Identifier(db)))

    with connect(db) as conn:
        me = conn.execute("select current_user").fetchone()[0]
        for role in ("ctf_migrator", "flagdesk_app", "vulnmart_app"):
            try:
                conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), sql.Identifier(me))) if role == "ctf_migrator" else None
            except Exception:
                pass
        conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO ctf_migrator, flagdesk_app, vulnmart_app").format(sql.Identifier(db)))
        conn.execute(sql.SQL("GRANT CREATE ON DATABASE {} TO ctf_migrator").format(sql.Identifier(db)))
        if args.revoke_public_connect:
            conn.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(db)))
            conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO ctf_migrator, flagdesk_app, vulnmart_app").format(sql.Identifier(db)))
        conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        conn.execute("REVOKE ALL ON SCHEMA public FROM flagdesk_app, vulnmart_app")
        for s in SCHEMAS:
            conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {} AUTHORIZATION ctf_migrator").format(sql.Identifier(s)))
            conn.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(s)))
        grants = {"flagdesk_app": ("identity", "flagdesk", "audit"), "vulnmart_app": ("vulnmart",)}
        for role, schemas in grants.items():
            for s in schemas:
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(s), sql.Identifier(role)))
                conn.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}").format(sql.Identifier(s), sql.Identifier(role)))
                conn.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}").format(sql.Identifier(s), sql.Identifier(role)))
                conn.execute(sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE ctf_migrator IN SCHEMA {} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(sql.Identifier(s), sql.Identifier(role)))
                conn.execute(sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE ctf_migrator IN SCHEMA {} GRANT USAGE, SELECT ON SEQUENCES TO {}").format(sql.Identifier(s), sql.Identifier(role)))
        conn.execute("ALTER ROLE flagdesk_app SET search_path = flagdesk, identity, audit")
        conn.execute("ALTER ROLE vulnmart_app SET search_path = vulnmart")
        conn.execute("ALTER ROLE ctf_migrator SET search_path = public")
        conn.execute(sql.SQL("ALTER ROLE flagdesk_app CONNECTION LIMIT {}").format(sql.Literal(args.flagdesk_conn_limit)))
        conn.execute(sql.SQL("ALTER ROLE vulnmart_app CONNECTION LIMIT {}").format(sql.Literal(args.vulnmart_conn_limit)))
        conn.execute(sql.SQL("ALTER ROLE vulnmart_app SET statement_timeout = {}").format(sql.Literal(args.vulnmart_statement_timeout)))
        conn.execute("ALTER ROLE vulnmart_app SET idle_in_transaction_session_timeout = '15s'")
        conn.execute("ALTER ROLE flagdesk_app SET statement_timeout = '10s'")
        conn.execute("ALTER ROLE flagdesk_app SET idle_in_transaction_session_timeout = '15s'")
    print(f"bootstrap complete for database {db}: schemas {', '.join(SCHEMAS)}; roles ctf_migrator, flagdesk_app, vulnmart_app")


if __name__ == "__main__":
    main()
