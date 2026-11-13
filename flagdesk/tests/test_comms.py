import pyotp
from fastapi.testclient import TestClient

from app.main import app
from conftest import H, make_user


def org():
    o = TestClient(app)
    r = o.post("/api/organizer/login", json={"username": "org.alpha", "password": "Alpha-Pass-12345", "totp": pyotp.TOTP("JBSWY3DPEHPK3PXP").now()}, headers=H)
    assert r.status_code == 200
    return o


def test_wordlists_seeded_hidden_then_released_per_lab(client):
    c, _ = make_user(client, "wl_user1")
    assert c.get("/api/resources").json() == []
    assert c.get("/api/resources/usernames/download").status_code == 404
    o = org()
    items = {r["id"]: r for r in o.get("/api/admin/resources").json()}
    for rid in ("usernames", "xss-reflected", "xss-stored", "xss-dom", "sqli"):
        assert rid in items and items[rid]["lines"] > 10 and items[rid]["released_labs"] == []
    r = o.patch("/api/admin/resources/usernames", json={"released_labs": ["LAB-01", "LAB-02"]}, headers=H)
    assert r.status_code == 200 and r.json()["released_labs"] == ["LAB-01", "LAB-02"]
    got = c.get("/api/resources").json()
    assert [x["id"] for x in got] == ["usernames"] and got[0]["released_labs"] == ["LAB-01", "LAB-02"]
    d = c.get("/api/resources/usernames/download")
    assert d.status_code == 200 and "ops.recovery" in d.text and d.headers["content-type"].startswith("text/plain")
    assert "attachment" in d.headers["content-disposition"] and d.headers["x-content-type-options"] == "nosniff"
    assert c.get("/api/resources/sqli/download").status_code == 404
    n = c.get("/api/notifications").json()
    assert n and n[0]["kind"] == "wordlist" and n[0]["link"] == "/api/resources/usernames/download"
    o.patch("/api/admin/resources/usernames", json={"released_labs": []}, headers=H)
    assert c.get("/api/resources").json() == []
    assert c.get("/api/resources/usernames/download").status_code == 404


def test_announcement_push_validation_and_delete(client):
    c, _ = make_user(client, "wl_user2")
    o = org()
    bad = o.post("/api/admin/announcements", json={"title": "x", "link": "javascript:alert(1)"}, headers=H)
    assert bad.status_code == 422
    assert o.post("/api/admin/announcements", json={"title": "x", "link": "//evil.example/x"}, headers=H).status_code == 422
    assert o.post("/api/admin/announcements", json={"title": "x", "challenge_id": "LAB-99"}, headers=H).status_code == 422
    ok = o.post("/api/admin/announcements", json={"title": "Hints open", "body": "Check LAB-07", "link": "https://example.com/list.txt", "challenge_id": "LAB-07"}, headers=H)
    assert ok.status_code == 200
    seen = c.get("/api/notifications").json()
    assert seen[0]["title"] == "Hints open" and seen[0]["kind"] == "link"
    assert o.delete(f"/api/admin/announcements/{ok.json()['id']}", headers=H).status_code == 200
    assert all(a["title"] != "Hints open" for a in c.get("/api/notifications").json())


def test_participants_cannot_use_organizer_endpoints(client):
    c, _ = make_user(client, "wl_user3")
    assert c.post("/api/admin/announcements", json={"title": "hi"}, headers=H).status_code == 404
    assert c.patch("/api/admin/resources/sqli", json={"released_labs": ["LAB-10"]}, headers=H).status_code == 404
    assert c.get("/api/admin/resources").status_code == 404
    assert TestClient(app).get("/api/notifications").status_code == 401
    assert TestClient(app).get("/api/resources/sqli/download").status_code == 401


def test_custom_wordlist_upload_and_validation(client):
    o = org()
    assert o.post("/api/admin/resources", json={"title": "t", "filename": "../x", "content": "a"}, headers=H).status_code == 422
    assert o.post("/api/admin/resources", json={"title": "t", "filename": "x.txt", "content": "a", "labs": ["LAB-99"]}, headers=H).status_code == 422
    r = o.post("/api/admin/resources", json={"title": "Custom", "filename": "custom.txt", "content": "a\nb\nc", "labs": ["LAB-04"]}, headers=H)
    assert r.status_code == 200 and r.json()["lines"] == 3 and r.json()["released_labs"] == []
    assert o.patch("/api/admin/resources/" + r.json()["id"], json={"released_labs": ["LAB-77"]}, headers=H).status_code == 422
    assert o.delete("/api/admin/resources/" + r.json()["id"], headers=H).status_code == 200


def test_payload_lists_cover_expected_content():
    import os
    base = os.path.join(os.path.dirname(__file__), "..", "wordlists")
    def rows(n):
        return [x for x in open(os.path.join(base, n), encoding="utf-8").read().splitlines() if x.strip()]
    assert len(rows("usernames.txt")) == 50 and {"vault.audit", "ops.recovery"} <= set(rows("usernames.txt"))
    import re
    m = re.compile(r"<\s*[a-z!/]", re.I)
    assert all(m.search(x) for x in rows("xss-reflected.txt")) and all(m.search(x) for x in rows("xss-stored.txt"))
    assert any("training_secrets" in x for x in rows("sqli.txt"))
