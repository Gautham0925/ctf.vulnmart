import os

from alembic import context
from sqlalchemy import create_engine, text

from app.db import Base
from app import models  # noqa: F401

SCHEMA = "vulnmart"
target_metadata = Base.metadata


def _url():
    url = os.environ.get("MIGRATOR_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("MIGRATOR_DATABASE_URL is required (direct Postgres connection as ctf_migrator, not PgBouncer)")
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgresql+psycopg://" + url[len(prefix):]
    return url


def run():
    engine = create_engine(_url(), connect_args={"options": f"-c search_path={SCHEMA}"})
    with engine.connect() as conn:
        conn.execute(text(f"set search_path to {SCHEMA}"))
        conn.commit()
        context.configure(connection=conn, target_metadata=target_metadata, version_table_schema=SCHEMA, include_schemas=False, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
