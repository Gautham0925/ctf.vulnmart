import os

import psycopg
import pytest

from app.core.config import get_settings
from app.integration import flagdesk, participant
from tests.conftest import ADMIN_PASSWORD, SessionLocal, TEST_PARTICIPANT, auth, expected, fake_flag, login, sso_cookie


def test_flag_bound_to_participant(client, training):
    other = "33333333-3333-4333-8333-333333333333"
    assert fake_flag(TEST_PARTICIPANT, "LAB-01") != fake_flag(other, "LAB-01")
    r = client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert r.json()["detail"]["audit_reference"] == expected("LAB-01")
    client.cookies.set("vm_sso", sso_cookie(other, "other.player"))
    r = client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert r.json()["detail"]["audit_reference"] == expected("LAB-01", other)
    assert r.json()["detail"]["audit_reference"] != expected("LAB-01")


def test_no_participant_context_gets_no_flag(anon_client, training):
    r = anon_client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert "VULN{" not in r.text and participant.NOTICE in r.text


def test_forged_outer_cookie_rejected(anon_client, training):
    import jwt
    forged = jwt.encode({"iss": "vulnmart-shop", "aud": participant.AUDIENCE, "sub": TEST_PARTICIPANT, "sid": "x", "iat": 1, "exp": 4102444800}, "attacker-key" * 4, algorithm="HS256")
    anon_client.cookies.set("vm_sso", forged)
    r = anon_client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert "VULN{" not in r.text


def test_inner_jwt_confusion_cannot_forge_outer_identity(anon_client, training):
    from tests.conftest import admin_claims, forge_hs256
    token = forge_hs256(admin_claims())
    anon_client.cookies.set("vm_sso", token)
    r = anon_client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert "VULN{" not in r.text


def test_revoked_flagdesk_session_blocks_flag(client, training, monkeypatch):
    monkeypatch.setattr(flagdesk, "enabled", lambda: True)
    monkeypatch.setattr(flagdesk, "session_active", lambda sid, ttl=10.0: False)
    r = client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert "VULN{" not in r.text


def test_flagdesk_outage_degrades_without_static_flag(client, training, monkeypatch):
    monkeypatch.setattr(flagdesk, "issue_flag", lambda pid, lab: None)
    r = client.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert r.status_code == 401 and "VULN{" not in r.text and "unavailable" in r.text


def test_sentinels_never_leak_and_cannot_be_planted(client, training):
    from app.core.flags_config import sentinel
    h = auth(login(client, "gautham.shop")["access_token"])
    r = client.post("/api/users/me/addresses", headers=h, json={"label": "x", "recipient": "A B", "line1": "1 Road", "city": "C", "state": "S", "postal_code": "400001", "delivery_notes": sentinel("LAB-06")})
    assert r.status_code == 422
    for path in ["/api/orders", "/api/users/me/addresses", "/api/labs"]:
        assert "[[VMS:" not in client.get(path, headers=h).text


def test_registration_disabled_when_integrated(client, monkeypatch):
    from app.routers import auth as auth_router
    monkeypatch.setattr(auth_router.settings, "local_registration_enabled", False)
    r = client.post("/api/auth/register", json={"username": "newbie1", "email": "n@example.com", "full_name": "New Bie", "password": "Password#123"})
    assert r.status_code == 403


def test_mode_and_reset_locked_when_integrated(client, training, monkeypatch):
    from app.routers import admin as admin_router
    monkeypatch.setattr(admin_router.settings, "ctf_enabled", True)
    h = auth(login(client, "admin", ADMIN_PASSWORD)["access_token"])
    assert client.put("/api/admin/config/mode", headers=h, json={"mode": "secure"}).status_code == 403
    assert client.post("/api/admin/labs/LAB-04/reset", headers=h).status_code == 403


def test_sso_callback_provisions_user_without_password(anon_client, monkeypatch):
    from app.routers import sso as sso_router
    pid = "44444444-4444-4444-8444-444444444444"
    monkeypatch.setattr(flagdesk, "exchange_code", lambda code, uri: {"assertion": "a"})
    monkeypatch.setattr(flagdesk, "verify_assertion", lambda t: {"sub": pid, "preferred_username": "new.player", "role": "participant", "sid": "sid-1"})
    anon_client.cookies.set("vm_sso_state", "st4te", path="/api/sso")
    r = anon_client.get("/api/sso/callback", params={"code": "c", "state": "st4te"}, follow_redirects=False)
    assert r.status_code == 302
    assert participant.read_cookie(anon_client.cookies.get("vm_sso"))["sub"] == pid
    s = anon_client.post("/api/sso/session", headers={"x-vm": "1"})
    assert s.status_code == 200 and s.json()["user"]["username"] == "new.player"
    bad = anon_client.post("/api/auth/login", json={"username": "new.player", "password": "anything-at-all"})
    assert bad.status_code in (401, 404)
    with SessionLocal() as db:
        from app.models import User
        u = db.query(User).filter(User.identity_uuid == pid).one()
        assert u.password_hash == "!sso-only" and u.email.endswith("@sso.invalid")


def test_sso_callback_rejects_bad_state_and_organizer(anon_client, monkeypatch):
    anon_client.cookies.set("vm_sso_state", "good", path="/api/sso")
    assert anon_client.get("/api/sso/callback", params={"code": "c", "state": "evil"}).status_code == 400
    monkeypatch.setattr(flagdesk, "exchange_code", lambda code, uri: {"assertion": "a"})
    monkeypatch.setattr(flagdesk, "verify_assertion", lambda t: {"sub": "x", "preferred_username": "o", "role": "organizer", "sid": "s"})
    assert anon_client.get("/api/sso/callback", params={"code": "c", "state": "good"}).status_code == 400


def test_sso_session_requires_header_and_cookie(anon_client):
    assert anon_client.post("/api/sso/session").status_code == 403
    assert anon_client.post("/api/sso/session", headers={"x-vm": "1"}).status_code == 401


@pytest.mark.skipif(not os.environ.get("VULNMART_DB_PASSWORD"), reason="needs bootstrapped roles")
def test_vulnmart_role_cannot_read_identity_or_flagdesk():
    dsn = f"postgresql://vulnmart_app:{os.environ['VULNMART_DB_PASSWORD']}@localhost:5432/ctf_dev"
    with psycopg.connect(dsn, autocommit=True) as c:
        assert c.execute("show search_path").fetchone()[0] == "vulnmart"
        assert c.execute("select count(*) from users").fetchone()[0] >= 0
        for q in ("select * from identity.participants", "select * from flagdesk.issued_flags", "select * from audit.audit_events", "select * from flagdesk.solves"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(q)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("create table vulnmart.evil(x int)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("create table public.evil(x int)")
