import os

os.environ.setdefault("DATABASE_URL", os.environ.get("MIGRATOR_DATABASE_URL", ""))
os.environ.setdefault("FLAG_SECRET", "x" * 40)

from alembic import context
from sqlalchemy import create_engine, text

from app.db import Base
from app import models  # noqa: F401

SCHEMAS = ("identity", "flagdesk", "audit")
VERSION_SCHEMA = "flagdesk"
target_metadata = Base.metadata


def _url():
    url = os.environ.get("MIGRATOR_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("MIGRATOR_DATABASE_URL is required (direct Postgres connection as ctf_migrator, not PgBouncer)")
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgresql+psycopg://" + url[len(prefix):]
    return url


def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table" and name == "alembic_version":
        return False
    schema = getattr(obj, "schema", None)
    if type_ == "table" and schema not in SCHEMAS:
        return False
    return True


def run():
    engine = create_engine(_url())
    with engine.connect() as conn:
        for s in SCHEMAS:
            conn.execute(text(f"create schema if not exists {s}"))
        conn.commit()
        context.configure(connection=conn, target_metadata=target_metadata, version_table_schema=VERSION_SCHEMA, include_schemas=True, include_object=include_object, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
