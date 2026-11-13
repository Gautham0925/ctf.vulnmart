import hashlib
import os
import uuid

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://ctf_migrator:dev-migrator-pw@localhost:5432/ctf_dev?options=-csearch_path%3Dvulnmart")
os.environ.setdefault("SHOP_SESSION_SECRET", "t" * 48)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import seed
from app.core.mode import set_mode
from app.core.security import PUBLIC_KEY_PEM
from app.db import SessionLocal
from app.main import app

PASSWORD = "Shop#Pass2026"
ADMIN_PASSWORD = "Adm1n#Market2026"


@pytest.fixture(scope="session", autouse=True)
def fresh_database():
    seed.run(reset=True)
    yield


TEST_PARTICIPANT = "11111111-1111-4111-8111-111111111111"


def fake_flag(participant_id, lab_id):
    return "VULN{" + hashlib.sha256(f"{participant_id}|{lab_id}".encode()).hexdigest()[:32].upper() + "}"


def expected(lab_id, participant_id=TEST_PARTICIPANT):
    return fake_flag(participant_id, lab_id)


@pytest.fixture(autouse=True)
def stub_flagdesk(monkeypatch):
    from app.integration import flagdesk
    monkeypatch.setattr(flagdesk, "issue_flag", lambda pid, lab: fake_flag(pid, lab))
    monkeypatch.setattr(flagdesk, "session_active", lambda sid, ttl=10.0: True)


def sso_cookie(participant_id=TEST_PARTICIPANT, username="ctf.player"):
    from app.integration import participant
    return participant.make_cookie(participant_id, username, "sid-test")


@pytest.fixture()
def client():
    with TestClient(app, base_url="http://localhost") as c:
        c.cookies.set("vm_sso", sso_cookie())
        yield c


@pytest.fixture()
def anon_client():
    with TestClient(app, base_url="http://localhost") as c:
        yield c


@pytest.fixture()
def training():
    with SessionLocal() as db:
        set_mode(db, "training")
    yield
    with SessionLocal() as db:
        set_mode(db, "training")


@pytest.fixture()
def secure():
    with SessionLocal() as db:
        set_mode(db, "secure")
    yield
    with SessionLocal() as db:
        set_mode(db, "training")


def login(client, username, password=PASSWORD):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge_hs256(claims: dict, key: bytes = PUBLIC_KEY_PEM) -> str:
    header = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64e(json.dumps(claims).encode())
    sig = hmac.new(key, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64e(sig)}"


def admin_claims(sub=1):
    ts = int(time.time())
    return {"sub": str(sub), "role": "admin", "sid": "forged", "stage": "full", "typ": "access", "iss": "https://vulnmarket.local", "aud": "vulnmarket-web", "iat": ts, "exp": ts + 600}
