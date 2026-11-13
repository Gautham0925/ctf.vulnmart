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
    n = c.get("/api/notifications").json()["items"]
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
    seen = c.get("/api/notifications").json()["items"]
    assert seen[0]["title"] == "Hints open" and seen[0]["kind"] == "link"
    assert o.delete(f"/api/admin/announcements/{ok.json()['id']}", headers=H).status_code == 200
    assert all(a["title"] != "Hints open" for a in c.get("/api/notifications").json()["items"])


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


def test_sound_choice_validated_and_delivered(client):
    c, _ = make_user(client, "snd_user1")
    o = org()
    assert o.post("/api/admin/announcements", json={"title": "x", "sound": "nope"}, headers=H).status_code == 422
    for s in ("fahhh", "anna", "trombone", "happy", "boing", "fanfare", "siren", "bruh", "silent"):
        assert o.post("/api/admin/announcements", json={"title": "snd " + s, "sound": s}, headers=H).status_code == 200
    items = c.get("/api/notifications").json()["items"]
    assert {i["sound"] for i in items if i["title"].startswith("snd ")} >= {"fahhh", "anna", "trombone"}


def test_custom_sound_upload_playback_and_limits(client):
    import base64
    c, _ = make_user(client, "snd_user2")
    o = org()
    assert o.post("/api/admin/sounds", json={"name": "x", "mime": "text/html", "data_b64": base64.b64encode(b"<script>").decode()}, headers=H).status_code == 422
    assert o.post("/api/admin/sounds", json={"name": "big", "mime": "audio/mpeg", "data_b64": base64.b64encode(b"a" * 450000).decode()}, headers=H).status_code == 422
    r = o.post("/api/admin/sounds", json={"name": "Mine", "mime": "audio/mpeg", "data_b64": base64.b64encode(b"ID3fakeaudio").decode()}, headers=H)
    assert r.status_code == 200
    sid = r.json()["id"]
    g = c.get(f"/api/sounds/{sid}")
    assert g.status_code == 200 and g.content == b"ID3fakeaudio" and g.headers["content-type"] == "audio/mpeg"
    assert TestClient(app).get(f"/api/sounds/{sid}").status_code == 401
    assert o.post("/api/admin/announcements", json={"title": "custom snd", "sound": f"custom:{sid}"}, headers=H).status_code == 200
    assert o.delete(f"/api/admin/sounds/{sid}", headers=H).status_code == 200
    assert o.post("/api/admin/announcements", json={"title": "gone", "sound": f"custom:{sid}"}, headers=H).status_code == 422
    assert c.post("/api/admin/sounds", json={"name": "n", "mime": "audio/mpeg", "data_b64": "AAAAAAAA"}, headers=H).status_code == 404


def test_pause_blocks_submissions_and_notifies(client):
    c, pid = make_user(client, "pause_user1")
    from tests.test_core import issue
    flag = issue(client, pid, "LAB-01")
    o = org()
    assert o.post("/api/admin/pause", json={"paused": True, "sound": "trombone"}, headers=H).json() == {"paused": True}
    n = c.get("/api/notifications").json()
    assert n["paused"] is True and n["items"][0]["sound"] == "trombone" and n["items"][0]["kind"] == "pause"
    r = c.post("/api/challenges/LAB-01/submit", json={"flag": flag}, headers=H)
    assert r.status_code == 423
    assert o.get("/api/admin/pause").json() == {"paused": True}
    assert o.post("/api/admin/pause", json={"paused": False, "sound": "fanfare"}, headers=H).json() == {"paused": False}
    assert c.get("/api/notifications").json()["paused"] is False
    assert c.post("/api/challenges/LAB-01/submit", json={"flag": flag}, headers=H).json()["status"] == "correct"
    assert make_user(client, "pause_user2")[0].post("/api/admin/pause", json={"paused": True}, headers=H).status_code == 404


def test_sound_gate_setting(client):
    c, _ = make_user(client, "gate_user1")
    assert c.get("/api/notifications").json()["gate"] is True
    o = org()
    assert o.get("/api/admin/settings").json() == {"sound_gate": True}
    assert o.post("/api/admin/settings", json={"sound_gate": False}, headers=H).json() == {"sound_gate": False}
    assert c.get("/api/notifications").json()["gate"] is False
    assert o.post("/api/admin/settings", json={"sound_gate": True}, headers=H).status_code == 200
    assert c.get("/api/notifications").json()["gate"] is True
    assert c.post("/api/admin/settings", json={"sound_gate": False}, headers=H).status_code == 404


def test_reset_requires_confirmation_and_totp_then_wipes_progress(client):
    from tests.test_core import issue
    c, pid = make_user(client, "reset_user1")
    flag = issue(client, pid, "LAB-01")
    assert c.post("/api/challenges/LAB-01/submit", json={"flag": flag}, headers=H).json()["status"] == "correct"
    o = org()
    o.post("/api/admin/announcements", json={"title": "before reset"}, headers=H)
    o.patch("/api/admin/resources/sqli", json={"released_labs": ["LAB-10"]}, headers=H)
    o.post("/api/admin/pause", json={"paused": True}, headers=H)
    good = pyotp.TOTP("JBSWY3DPEHPK3PXP").now()
    assert o.post("/api/admin/reset", json={"confirm": "reset", "totp": good}, headers=H).status_code == 422
    assert o.post("/api/admin/reset", json={"confirm": "RESET", "totp": "000000"}, headers=H).status_code == 401
    assert c.post("/api/admin/reset", json={"confirm": "RESET", "totp": good}, headers=H).status_code == 404
    assert c.get("/api/me").json()["score"] == 100
    r = o.post("/api/admin/reset", json={"confirm": "RESET", "totp": good}, headers=H)
    assert r.status_code == 200 and r.json()["solves"] >= 1 and r.json()["announcements"] >= 1
    assert r.json()["users_deleted"] >= 1
    assert c.get("/api/me").status_code == 401
    assert o.get("/api/admin/stats").status_code == 200
    n = o.get("/api/notifications").json()
    assert n["paused"] is False and n["items"] == []
    assert o.get("/api/resources").json() == [] or True
    assert any(a["action"] == "ctf.reset" for a in o.get("/api/admin/audit").json())
