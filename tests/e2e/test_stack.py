import os
import re
import time
import uuid

import httpx
import psycopg
import pyotp
import pytest

H = {"x-fd": "1"}


class Browser:
    def __init__(self, stack, name=None):
        self.s = stack
        self.fd = httpx.Client(base_url=stack.FD_URL, timeout=15)
        self.vm = httpx.Client(base_url=stack.VM_URL, timeout=15)
        self.name = name or "p" + uuid.uuid4().hex[:10]
        self.pid = None

    def register(self):
        r = self.fd.post("/api/register", json={"username": self.name, "password": "Password-123"}, headers=H)
        assert r.status_code == 200, r.text
        self.pid = r.json()["id"]

    def sso(self):
        r = self.vm.get("/api/sso/login", follow_redirects=False)
        assert r.status_code == 302
        loc = r.headers["location"]
        assert loc.startswith(self.s.FD_URL + "/sso/authorize")
        path = loc[len(self.s.FD_URL):]
        r = self.fd.get(path, follow_redirects=False)
        assert r.status_code == 302, r.text
        cb = r.headers["location"]
        assert cb.startswith(self.s.VM_URL + "/api/sso/callback")
        r = self.vm.get(cb[len(self.s.VM_URL):], follow_redirects=False)
        assert r.status_code == 302, r.text
        r = self.vm.post("/api/sso/session", headers={"x-vm": "1"})
        assert r.status_code == 200, r.text
        self.tokens = r.json()
        return r.json()

    def lab01(self):
        r = self.vm.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
        return r.json()["detail"]["audit_reference"]

    def submit(self, chal, flag):
        return self.fd.post(f"/api/challenges/{chal}/submit", json={"flag": flag}, headers=H).json()

    def score(self):
        return self.fd.get("/api/me").json()["score"]


def full(stack):
    b = Browser(stack)
    b.register()
    b.sso()
    return b


def test_full_flow_and_flag_binding(stack):
    a, b = full(stack), full(stack)
    assert a.tokens["user"]["username"] == a.name
    fa, fb = a.lab01(), b.lab01()
    assert re.fullmatch(r"VULN\{[0-9A-F]{32}\}", fa) and fa != fb
    assert a.lab01() == fa
    assert b.submit("LAB-01", fa)["status"] == "incorrect"
    assert a.submit("LAB-01", fa) == {"status": "correct", "points": 100}
    assert a.submit("LAB-01", fa)["status"] == "already_solved"
    assert a.score() == 100 and b.score() == 0
    assert b.submit("LAB-01", fb)["status"] == "correct"


def test_username_identical_in_both_apps_and_single_uuid(stack):
    a = full(stack)
    assert a.tokens["user"]["username"] == a.name
    me = a.vm.get("/api/sso/me").json()
    assert me["participant_id"] == a.pid and me["username"] == a.name
    with psycopg.connect(os.environ.get("ADMIN_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres").rsplit("/", 1)[0] + "/ctf_dev") as c:
        row = c.execute("select identity_uuid, email, password_hash from vulnmart.users where username=%s", (a.name,)).fetchone()
    assert row[0] == a.pid and row[1] == f"{a.pid}@sso.invalid" and row[2] == "!sso-only"


def test_local_shop_registration_closed_and_no_password_login(stack):
    a = full(stack)
    r = a.vm.post("/api/auth/register", json={"username": "shopreg1", "email": "s@example.com", "full_name": "S R", "password": "Password#123"})
    assert r.status_code == 403
    r = httpx.post(stack.VM_URL + "/api/auth/login", json={"username": a.name, "password": "Password-123"})
    assert r.status_code in (401, 404)


def test_lab_flags_across_labs_and_scoring(stack):
    a = full(stack)
    h = {"Authorization": "Bearer " + a.tokens["access_token"]}
    r = a.vm.post("/api/auth/refresh", json={"refresh_token": a.tokens["refresh_token"]})
    assert r.status_code == 200 and "session_audit" not in r.json()
    a.vm.post("/api/auth/logout", headers=h)
    r = a.vm.post("/api/auth/refresh", json={"refresh_token": a.tokens["refresh_token"]})
    f4 = r.json()["session_audit"]["reference"]
    assert a.submit("LAB-04", f4)["status"] == "correct"
    r = a.vm.post("/api/auth/forgot-password", json={"identifier": "ops.recovery"})
    f2 = r.json()["recovery_ticket"]
    assert a.submit("LAB-02", f2)["status"] == "correct"
    assert a.submit("LAB-05", f2)["status"] == "incorrect"
    assert a.score() == 250
    r = a.vm.get("/api/products/search", params={"q": "zzz%' UNION SELECT 1,name,value,0,0,0,NULL,NULL FROM training_secrets--"})
    brands = [i["brand"] for i in r.json()["items"]]
    f10 = next(x for x in brands if x and x.startswith("VULN{"))
    assert a.submit("LAB-10", f10)["status"] == "correct"
    assert not any("[[VMS:" in (x or "") for x in brands)


def test_idor_lab03_and_lab06_flags_are_personal(stack):
    a, b = full(stack), full(stack)
    out = {}
    for who in (a, b):
        h = {"Authorization": "Bearer " + who.tokens["access_token"]}
        found = None
        for oid in range(1, 60):
            r = who.vm.get(f"/api/orders/{oid}", headers=h)
            if r.status_code == 200 and r.json()["gift_message"]:
                found = r.json()["gift_message"]
                break
        out[who.name] = found
    assert out[a.name].startswith("VULN{") and out[a.name] != out[b.name]
    assert a.submit("LAB-03", out[a.name])["status"] == "correct"
    assert b.submit("LAB-03", out[a.name])["status"] == "incorrect"


def test_logout_at_flagdesk_stops_flag_issuance(stack):
    a = full(stack)
    assert a.lab01().startswith("VULN{")
    a.fd.post("/api/logout", headers=H)
    time.sleep(11)
    r = a.vm.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"})
    assert "VULN{" not in r.text


def test_organizer_isolation_and_dashboard(stack):
    a = full(stack)
    a.lab01()
    o = httpx.Client(base_url=stack.FD_URL, timeout=15)
    r = o.post("/api/organizer/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345", "totp": pyotp.TOTP("JBSWY3DPEHPK3PXP").now()}, headers=H)
    assert r.status_code == 200
    stats = o.get("/api/admin/stats").json()
    parts = o.get("/api/admin/participants").json()
    assert stats["participants"] == len(parts) and all(p["username"] not in ("org.alpha", "org.beta") for p in parts)
    assert a.fd.get("/api/admin/stats").status_code == 404
    board = a.fd.get("/api/scoreboard").text
    assert "org.alpha" not in board and "org.beta" not in board
    assert httpx.post(stack.FD_URL + "/internal/objectives", json={"participant_id": a.pid, "lab_id": "LAB-01"}).status_code == 401


def test_shop_never_stores_flags_or_secrets_in_db(stack):
    with psycopg.connect("postgresql://postgres:postgres@localhost:5432/ctf_dev") as c:
        cols = c.execute("select table_schema, table_name, column_name from information_schema.columns where table_schema='vulnmart' and data_type in ('character varying','text','json','jsonb')").fetchall()
        for s, t, col in cols:
            n = c.execute(f'select count(*) from "{s}"."{t}" where cast("{col}" as text) like %s', ("%VULN{%",)).fetchone()[0]
            assert n == 0, (t, col)


def test_wrong_attempt_rate_limit(stack):
    a = full(stack)
    codes = [a.fd.post("/api/challenges/LAB-05/submit", json={"flag": "VULN{" + "0" * 32 + "}"}, headers=H).status_code for _ in range(12)]
    assert 429 in codes and codes[:8] == [200] * 8
