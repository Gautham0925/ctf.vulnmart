import concurrent.futures as cf
import re
import uuid

import pyotp
from fastapi.testclient import TestClient

from app import flags, security
from app.main import app
from tests.conftest import H, SVC, make_user


def issue(client, pid, lab="LAB-01"):
    r = client.post("/internal/objectives", json={"participant_id": pid, "lab_id": lab}, headers=SVC)
    assert r.status_code == 200, r.text
    return r.json()["flag"]


def test_flag_format_and_properties():
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    f = flags.derive("e", a, "LAB-01", 1)
    assert re.fullmatch(r"VULN\{[0-9A-F]{32}\}", f)
    assert f == flags.derive("e", a, "LAB-01", 1)
    assert f != flags.derive("e", b, "LAB-01", 1)
    assert f != flags.derive("e", a, "LAB-02", 1)
    assert f != flags.derive("e2", a, "LAB-01", 1)
    assert f != flags.derive("e", a, "LAB-01", 2)


def test_no_legacy_prefix_anywhere(client):
    pid = make_user(client, "legacycheck")[1]
    assert issue(client, pid).startswith("VULN{")
    r = client.get("/api/config")
    assert "FLAG{" not in r.text


def test_register_login_and_enumeration(client):
    c, pid = make_user(client, "alice_t")
    assert c.get("/api/me").json()["username"] == "alice_t"
    bad1 = TestClient(app).post("/api/login", json={"username": "alice_t", "password": "nope-nope"}, headers=H)
    bad2 = TestClient(app).post("/api/login", json={"username": "ghost_user", "password": "nope-nope"}, headers=H)
    assert bad1.status_code == bad2.status_code == 401 and bad1.json() == bad2.json()
    ok = TestClient(app).post("/api/login", json={"username": "ALICE_T", "password": "Password-123"}, headers=H)
    assert ok.status_code == 200


def test_username_collisions_and_reserved(client):
    make_user(client, "Bob.Smith")
    for name in ("bob.smith", "BOB.SMITH", "admin", "ops.admin", "alice.morgan", "org.alpha", "ORG.BETA", "organizer"):
        r = TestClient(app).post("/api/register", json={"username": name, "password": "Password-123"}, headers=H)
        assert r.status_code == 409 and r.json()["detail"] == "That username is not available", name


def test_organizers_hidden_and_two_only(client):
    c, _ = make_user(client, "plainuser")
    assert c.get("/api/admin/stats").status_code == 404
    board = c.get("/api/scoreboard").json()
    assert "org.alpha" not in str(board) and "org.beta" not in str(board)
    o = TestClient(app)
    r = o.post("/api/organizer/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345", "totp": pyotp.TOTP("JBSWY3DPEHPK3PXP").now()}, headers=H)
    assert r.status_code == 200
    parts = o.get("/api/admin/participants").json()
    assert all(p["username"] not in ("org.alpha", "org.beta") for p in parts)
    assert o.get("/api/admin/stats").json()["participants"] == len(parts)
    pl = TestClient(app).post("/api/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345"}, headers=H)
    assert pl.status_code == 401
    wrong = TestClient(app).post("/api/organizer/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345", "totp": "000000"}, headers=H)
    assert wrong.status_code == 401
    from sqlalchemy import text
    from app.db import SessionLocal
    from sqlalchemy.exc import DBAPIError
    with SessionLocal() as db:
        try:
            db.execute(text("insert into identity.participants (id, username, username_norm, role, status, is_protected, pw_hash, created_at) values (gen_random_uuid(),'third','third','organizer','active',true,'x',now())"))
            db.commit()
            raised = False
        except DBAPIError:
            db.rollback()
            raised = True
    assert raised


def test_role_cannot_be_self_assigned(client):
    r = TestClient(app).post("/api/register", json={"username": "sneaky", "password": "Password-123", "role": "organizer"}, headers=H)
    assert r.status_code == 200 and r.json()["role"] == "participant"


def test_csrf_header_required(client):
    r = TestClient(app).post("/api/register", json={"username": "nocsrf", "password": "Password-123"})
    assert r.status_code == 403


def test_flag_lifecycle_and_scoring(client):
    c, pid = make_user(client, "solver1")
    flag = issue(client, pid)
    assert issue(client, pid) == flag
    r = c.post("/api/challenges/LAB-01/submit", json={"flag": flag}, headers=H)
    assert r.json() == {"status": "correct", "points": 100}
    r = c.post("/api/challenges/LAB-01/submit", json={"flag": flag}, headers=H)
    assert r.json()["status"] == "already_solved"
    assert c.get("/api/me").json()["score"] == 100


def test_wrong_challenge_and_foreign_flag(client):
    c1, p1 = make_user(client, "owner1")
    c2, p2 = make_user(client, "thief1")
    f1 = issue(client, p1)
    issue(client, p2)
    assert c2.post("/api/challenges/LAB-01/submit", json={"flag": f1}, headers=H).json()["status"] == "incorrect"
    f2_lab2 = issue(client, p1, "LAB-02")
    assert c1.post("/api/challenges/LAB-01/submit", json={"flag": f2_lab2}, headers=H).json()["status"] == "incorrect"
    assert c1.get("/api/me").json()["score"] == 0


def test_unissued_flag_never_accepted(client):
    c, pid = make_user(client, "noissue")
    forged = flags.derive("test-event", pid, "LAB-03", 1)
    assert c.post("/api/challenges/LAB-03/submit", json={"flag": forged}, headers=H).json()["status"] == "incorrect"


def test_legacy_format_rejected(client):
    c, pid = make_user(client, "legacyuser")
    issue(client, pid)
    assert c.post("/api/challenges/LAB-01/submit", json={"flag": "FLAG{IDOR_ORD€R_ACC€$$_003}"}, headers=H).json()["status"] == "incorrect"


def test_rotate_and_revoke(client):
    c, pid = make_user(client, "rotator")
    o = TestClient(app)
    o.post("/api/organizer/login", json={"username": "org.beta", "password": "Beta-Pass-12345", "totp": pyotp.TOTP("KRSXG5CTMVRXEZLU").now()}, headers=H)
    old = issue(client, pid)
    assert o.post("/api/admin/flags", json={"username": "rotator", "challenge_id": "LAB-01", "action": "rotate"}, headers=H).status_code == 200
    assert c.post("/api/challenges/LAB-01/submit", json={"flag": old}, headers=H).json()["status"] == "incorrect"
    new = issue(client, pid)
    assert new != old
    o.post("/api/admin/flags", json={"username": "rotator", "challenge_id": "LAB-01", "action": "revoke"}, headers=H)
    r = client.post("/internal/objectives", json={"participant_id": pid, "lab_id": "LAB-01"}, headers=SVC)
    assert r.status_code == 409
    assert c.post("/api/challenges/LAB-01/submit", json={"flag": new}, headers=H).json()["status"] == "incorrect"


def test_concurrent_duplicate_submission_scores_once(client):
    c, pid = make_user(client, "racer")
    flag = issue(client, pid, "LAB-05")

    def go(_):
        t = TestClient(app)
        t.cookies.update(c.cookies)
        return t.post("/api/challenges/LAB-05/submit", json={"flag": flag}, headers=H).json()["status"]

    with cf.ThreadPoolExecutor(20) as ex:
        res = list(ex.map(go, range(20)))
    assert res.count("correct") == 1
    assert c.get("/api/me").json()["score"] == 150
    from sqlalchemy import text
    from app.db import SessionLocal
    with SessionLocal() as db:
        assert db.execute(text("select count(*) from flagdesk.solves where participant_id=:p"), {"p": pid}).scalar() == 1


def test_service_auth_required(client):
    assert client.post("/internal/objectives", json={"participant_id": str(uuid.uuid4()), "lab_id": "LAB-01"}).status_code == 401
    assert client.post("/internal/objectives", json={"participant_id": str(uuid.uuid4()), "lab_id": "LAB-01"}, headers={"authorization": "Bearer wrong"}).status_code == 401


def test_sso_flow_and_revocation(client):
    c, pid = make_user(client, "ssouser")
    redirect = "http://shop.localhost:8081/api/sso/callback"
    r = c.get("/sso/authorize", params={"client_id": "vulnmart-shop", "redirect_uri": redirect, "state": "xyz"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith(redirect + "?code=")
    code = re.search(r"code=([^&]+)", r.headers["location"]).group(1)
    bad = client.post("/internal/sso/exchange", json={"code": code, "client_id": "vulnmart-shop", "redirect_uri": "http://evil/x"}, headers=SVC)
    assert bad.status_code == 400
    r2 = c.get("/sso/authorize", params={"client_id": "vulnmart-shop", "redirect_uri": redirect}, follow_redirects=False)
    code = re.search(r"code=([^&]+)", r2.headers["location"]).group(1)
    ex = client.post("/internal/sso/exchange", json={"code": code, "client_id": "vulnmart-shop", "redirect_uri": redirect}, headers=SVC)
    assert ex.status_code == 200
    from app import sso
    claims = sso.verify_assertion(ex.json()["assertion"], "vulnmart-shop")
    assert claims["sub"] == pid and claims["preferred_username"] == "ssouser" and {"iss", "aud", "exp", "iat", "sid", "jti"} <= set(claims)
    again = client.post("/internal/sso/exchange", json={"code": code, "client_id": "vulnmart-shop", "redirect_uri": redirect}, headers=SVC)
    assert again.status_code == 400
    assert client.post("/internal/identity/introspect", json={"sid": claims["sid"]}, headers=SVC).json()["active"] is True
    c.post("/api/logout", headers=H)
    assert client.post("/internal/identity/introspect", json={"sid": claims["sid"]}, headers=SVC).json()["active"] is False


def test_sso_rejects_unregistered_redirect(client):
    c, _ = make_user(client, "ssobad")
    r = c.get("/sso/authorize", params={"client_id": "vulnmart-shop", "redirect_uri": "http://evil.example/cb"}, follow_redirects=False)
    assert r.status_code == 400


def test_disabled_participant_loses_session(client):
    c, pid = make_user(client, "tobanned")
    o = TestClient(app)
    o.post("/api/organizer/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345", "totp": pyotp.TOTP("JBSWY3DPEHPK3PXP").now()}, headers=H)
    assert o.post(f"/api/admin/participants/{pid}/status", json={"status": "disabled"}, headers=H).status_code == 200
    assert c.get("/api/me").status_code == 401


def test_static_assets_and_no_legacy_prefix(client):
    assert client.get("/").status_code == 200
    js = client.get("/static/app.js")
    assert js.status_code == 200 and "FLAG{" not in js.text
    html = client.get("/").text
    assert "FLAG{" not in html and "VULN{" in html
