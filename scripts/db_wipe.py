import argparse
import os
import sys

from psycopg import sql

sys.path.insert(0, os.path.dirname(__file__))
from db_common import SCHEMAS, connect, target_db

SYSTEM = {"pg_catalog", "information_schema", "pg_toast"}


def main():
    ap = argparse.ArgumentParser(description="Destructive: removes the platform schemas (and with --everything every other user schema/table). Refuses unless you retype the database name.")
    ap.add_argument("--everything", action="store_true", help="also drop all other user schemas and the contents of public (full clear of the database)")
    ap.add_argument("--confirm-db-name", default="", help="must equal DB_NAME")
    ap.add_argument("--yes", action="store_true", help="skip the interactive prompt (still requires --confirm-db-name)")
    args = ap.parse_args()
    db = target_db()
    if args.confirm_db_name != db:
        sys.exit(f"refusing: pass --confirm-db-name {db}")
    with connect(db) as conn:
        host = conn.info.host
        rows = conn.execute("select table_schema, count(*) from information_schema.tables where table_schema not in ('pg_catalog','information_schema') group by 1 order by 1").fetchall()
        print(f"server {host}  database {db}")
        for s, n in rows:
            tag = "platform" if s in SCHEMAS else "OTHER"
            print(f"  schema {s:<20} {n:>4} tables  [{tag}]")
        foreign = [s for s, _ in rows if s not in SCHEMAS and s != "public"]
        publics = [n for s, n in rows if s == "public" and n]
        if (foreign or publics) and not args.everything:
            sys.exit("database contains non-platform objects; re-run with --everything if you really want to clear them too")
        if not args.yes:
            typed = input(f"Type the database name ({db}) to DELETE this data permanently: ").strip()
            if typed != db:
                sys.exit("aborted")
        for s in SCHEMAS:
            conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(s)))
        if args.everything:
            for s, _ in rows:
                if s in SCHEMAS or s in SYSTEM or s == "public":
                    continue
                conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(s)))
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
        print("done. Run scripts/db_bootstrap.py next.")


if __name__ == "__main__":
    main()
