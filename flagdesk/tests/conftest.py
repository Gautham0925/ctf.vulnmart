import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/ctf_test")
os.environ.update({
    "FLAG_SECRET": "f" * 48,
    "SESSION_SECRET": "s" * 48,
    "AUTO_CREATE_TABLES": "1",
    "ORGANIZER_1_USERNAME": "org.alpha", "ORGANIZER_1_PASSWORD": "Alpha-Pass-12345", "ORGANIZER_1_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
    "ORGANIZER_2_USERNAME": "org.beta", "ORGANIZER_2_PASSWORD": "Beta-Pass-12345", "ORGANIZER_2_TOTP_SECRET": "KRSXG5CTMVRXEZLU",
    "VULNMART_SERVICE_TOKEN_SHA256": __import__("hashlib").sha256(b"svc-token").hexdigest(),
    "SSO_PRIVATE_KEY_FILE": "/tmp/ctf_test_sso.pem",
    "ENVIRONMENT": "test",
    "EVENT_ID": "test-event",
})

import psycopg  # noqa: E402


def _reset():
    with psycopg.connect("postgresql://postgres:postgres@localhost:5432/postgres", autocommit=True) as c:
        if not c.execute("select 1 from pg_database where datname='ctf_test'").fetchone():
            c.execute("create database ctf_test")
    with psycopg.connect("postgresql://postgres:postgres@localhost:5432/ctf_test", autocommit=True) as c:
        for s in ("identity", "flagdesk", "audit"):
            c.execute(f"drop schema if exists {s} cascade")


_reset()

from fastapi.testclient import TestClient  # noqa: E402

from app import store  # noqa: E402
from app.main import app, cache  # noqa: E402

H = {"x-fd": "1"}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean():
    store.reset_memory()
    cache.clear()


def make_user(client, name, pw="Password-123"):
    c = TestClient(app)
    r = c.post("/api/register", json={"username": name, "password": pw}, headers=H)
    assert r.status_code == 200, r.text
    return c, r.json()["id"]


SVC = {"authorization": "Bearer svc-token"}
