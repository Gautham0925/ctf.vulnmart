import csv
import io
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlencode, urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import config, flags, security, services, sso, store
from app.db import Base, SessionLocal, engine, get_db
from app.deps import COOKIE, Principal, client_ip, csrf, hash_guard, principal_optional, require_organizer, require_participant, require_principal, require_service
from app.models import AuditEvent, AuthSession, Challenge, FlagState, IssuedFlag, LabMapping, Participant, Score, Solve, Submission, now

STATIC = os.path.join(os.path.dirname(__file__), "static")


class TTL:
    def __init__(self, ttl):
        self.ttl = ttl
        self.lock = threading.Lock()
        self.data = {}

    def get(self, key, build):
        with self.lock:
            hit = self.data.get(key)
            if hit and hit[0] > time.time():
                return hit[1]
        value = build()
        with self.lock:
            self.data[key] = (time.time() + self.ttl, value)
        return value

    def clear(self):
        with self.lock:
            self.data.clear()


cache = TTL(config.BOARD_TTL)


def startup():
    if len(config.FLAG_SECRET) < 32:
        raise RuntimeError("FLAG_SECRET must be set (>= 32 chars)")
    if config.PRODUCTION and (not config.SESSION_SECRET or config.SESSION_SECRET == config.FLAG_SECRET):
        raise RuntimeError("SESSION_SECRET must be set and differ from FLAG_SECRET in production")
    if config.AUTO_CREATE_TABLES:
        from app.ddl import create_all
        create_all(engine)
    sso.private_key()
    with SessionLocal() as db:
        services.seed_reserved(db)
        services.seed_event_and_challenges(db)
        services.bootstrap_organizers(db)


@asynccontextmanager
async def lifespan(app):
    startup()
    yield


app = FastAPI(title="FlagDesk", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if not request.url.path.startswith("/internal"):
        response.headers.setdefault("Cache-Control", "no-store" if request.url.path.startswith(("/api", "/sso")) else "no-cache")
    return response


def set_cookie(response, token, hours):
    response.set_cookie(COOKIE, token, max_age=hours * 3600, httponly=True, secure=config.COOKIE_SECURE, samesite="lax", path="/", domain=config.COOKIE_DOMAIN)


class Creds(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=200)
    code: str = Field(default="", max_length=100)


class OrganizerCreds(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)
    totp: str = Field(min_length=1, max_length=10)


class FlagIn(BaseModel):
    flag: str = Field(max_length=100)


def too_many(db, key, limit, window):
    return store.incr(key, window) > limit


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"ok": True}


@app.get("/api/config")
def public_config():
    return {"event_name": config.EVENT_NAME, "registration_open": config.REGISTRATION_OPEN, "code_required": bool(config.EVENT_CODE), "flag_format": "VULN{...}", "shop_url": config.SHOP_PUBLIC_URL}


@app.post("/api/register")
def register(body: Creds, request: Request, response: Response, db: Session = Depends(get_db)):
    csrf(request)
    ip = client_ip(request)
    if too_many(db, f"rl:reg:{ip}", config.REGISTER_IP_LIMIT, 3600):
        raise HTTPException(429, "Too many attempts")
    if not config.REGISTRATION_OPEN:
        raise HTTPException(403, "Registration is closed")
    if config.EVENT_CODE and not security.const_eq(body.code, config.EVENT_CODE):
        raise HTTPException(403, "Invalid event code")
    if not security.USERNAME_RE.match(body.username) or len(body.password) < 8:
        raise HTTPException(422, "Username must be 3-32 letters, digits, . _ - and password at least 8 characters")
    if config.MAX_PARTICIPANTS and db.scalar(select(func.count()).select_from(Participant).where(Participant.role == "participant")) >= config.MAX_PARTICIPANTS:
        raise HTTPException(403, "Event is full")
    with hash_guard():
        p = services.create_participant(db, body.username, body.password)
    if not p:
        db.rollback()
        raise HTTPException(409, "That username is not available")
    sid, token = services.open_session(db, p, ip)
    services.audit(db, "participant.register", p.id, "participant", ip=ip)
    db.commit()
    set_cookie(response, token, config.PARTICIPANT_SESSION_HOURS)
    cache.clear()
    return {"id": str(p.id), "username": p.username, "role": p.role}


@app.post("/api/login")
def login(body: Creds, request: Request, response: Response, db: Session = Depends(get_db)):
    csrf(request)
    ip = client_ip(request)
    norm = security.normalize_username(body.username)
    if too_many(db, f"rl:login:{norm}", config.LOGIN_LIMIT, config.LOGIN_WINDOW) or too_many(db, f"rl:loginip:{ip}", config.IP_LOGIN_LIMIT, config.LOGIN_WINDOW):
        raise HTTPException(429, "Too many attempts. Try again later.")
    p = db.scalar(select(Participant).where(Participant.username_norm == norm))
    with hash_guard():
        if p and p.role == "participant" and p.status == "active":
            ok = security.verify_password(body.password, p.pw_hash)
        else:
            security.burn_password_check(body.password)
            ok = False
    if not ok:
        raise HTTPException(401, "Invalid username or password")
    sid, token = services.open_session(db, p, ip)
    db.commit()
    set_cookie(response, token, config.PARTICIPANT_SESSION_HOURS)
    return {"id": str(p.id), "username": p.username, "role": p.role}


@app.post("/api/organizer/login")
def organizer_login(body: OrganizerCreds, request: Request, response: Response, db: Session = Depends(get_db)):
    csrf(request)
    ip = client_ip(request)
    norm = security.normalize_username(body.username)
    if too_many(db, f"rl:org:{norm}", 5, 900) or too_many(db, f"rl:orgip:{ip}", 30, 900):
        raise HTTPException(429, "Too many attempts. Try again later.")
    p = db.scalar(select(Participant).where(Participant.username_norm == norm))
    with hash_guard():
        if p and p.role == "organizer" and p.status == "active":
            ok = security.verify_password(body.password, p.pw_hash) and security.verify_totp(p.totp_secret_enc, body.totp)
        else:
            security.burn_password_check(body.password)
            ok = False
    if not ok:
        services.audit(db, "organizer.login_failed", None, "", norm[:40], ip=ip)
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    sid, token = services.open_session(db, p, ip)
    services.audit(db, "organizer.login", p.id, "organizer", ip=ip)
    db.commit()
    set_cookie(response, token, config.ORGANIZER_SESSION_HOURS)
    return {"id": str(p.id), "username": p.username, "role": p.role}


@app.post("/api/logout")
def logout(request: Request, response: Response, p: Principal = Depends(require_principal), db: Session = Depends(get_db)):
    services.revoke_session(db, p.sid)
    db.commit()
    response.delete_cookie(COOKIE, path="/", domain=config.COOKIE_DOMAIN)
    return {"ok": True}


@app.get("/api/me")
def me(p: Principal | None = Depends(principal_optional), db: Session = Depends(get_db)):
    if not p:
        raise HTTPException(401, "Not signed in")
    score = db.get(Score, p.id) if p.role == "participant" else None
    return {"id": str(p.id), "username": p.username, "role": p.role, "score": score.total if score else 0, "solved": score.solved if score else 0}


def _challenge_list(db, participant_id):
    solved = {r[0] for r in db.execute(select(Solve.challenge_id).where(Solve.participant_id == participant_id))}
    counts = cache.get("solve_counts", lambda: dict(db.execute(select(Solve.challenge_id, func.count()).group_by(Solve.challenge_id)).all()))
    rows = db.scalars(select(Challenge).where(Challenge.enabled.is_(True), Challenge.visible.is_(True)).order_by(Challenge.position, Challenge.id)).all()
    return [{"id": c.id, "title": c.title, "category": c.category, "description": c.description, "points": c.points, "solved": c.id in solved, "solve_count": counts.get(c.id, 0)} for c in rows]


@app.get("/api/challenges")
def challenges(p: Principal = Depends(require_participant), db: Session = Depends(get_db)):
    return _challenge_list(db, p.id)


@app.post("/api/challenges/{challenge_id}/submit")
def submit(challenge_id: str, body: FlagIn, p: Principal = Depends(require_participant), db: Session = Depends(get_db)):
    if store.incr(f"rl:sub:{p.id}", config.WRONG_WINDOW) > config.WRONG_LIMIT * 5:
        raise HTTPException(429, "Slow down")
    wrong_key = f"rl:wrong:{p.id}"
    if int(store.get(wrong_key) or 0) >= config.WRONG_LIMIT:
        raise HTTPException(429, "Too many wrong attempts. Wait a minute.")
    result = services.submit(db, p.id, challenge_id, body.flag.strip())
    if result["status"] == "incorrect":
        store.incr(wrong_key, config.WRONG_WINDOW)
    if result["status"] == "unknown":
        raise HTTPException(404, "Unknown challenge")
    if result["status"] == "correct":
        cache.clear()
    return result


def _board(db):
    rows = db.execute(
        select(Participant.username, Score.total, Score.solved, Score.last_solve_at)
        .join(Score, Score.participant_id == Participant.id)
        .where(Participant.role == "participant", Participant.status == "active", Score.solved > 0)
        .order_by(Score.total.desc(), Score.last_solve_at.asc(), Participant.username.asc())
        .limit(500)
    ).all()
    total = db.scalar(select(func.count()).select_from(Participant).where(Participant.role == "participant", Participant.status == "active"))
    return {"rows": [{"rank": i + 1, "username": r[0], "score": r[1], "solved": r[2], "last_solve_at": r[3].isoformat() if r[3] else None} for i, r in enumerate(rows)], "participants": total}


@app.get("/api/scoreboard")
def scoreboard(p: Principal = Depends(require_participant), db: Session = Depends(get_db)):
    return cache.get("board", lambda: _board(db))


@app.get("/api/admin/stats")
def admin_stats(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    return {
        "participants": db.scalar(select(func.count()).select_from(Participant).where(Participant.role == "participant")),
        "solves": db.scalar(select(func.count()).select_from(Solve)),
        "submissions": db.scalar(select(func.count()).select_from(Submission)),
        "wrong": db.scalar(select(func.count()).select_from(Submission).where(Submission.correct.is_(False))),
        "challenges": db.scalar(select(func.count()).select_from(Challenge)),
    }


@app.get("/api/admin/participants")
def admin_participants(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    rows = db.execute(select(Participant.id, Participant.username, Participant.status, Participant.created_at, Participant.last_login_at, func.coalesce(Score.total, 0), func.coalesce(Score.solved, 0)).outerjoin(Score, Score.participant_id == Participant.id).where(Participant.role == "participant").order_by(Participant.created_at.desc()).limit(1000)).all()
    return [{"id": str(r[0]), "username": r[1], "status": r[2], "created_at": r[3].isoformat(), "last_login_at": r[4].isoformat() if r[4] else None, "score": r[5], "solved": r[6]} for r in rows]


@app.get("/api/admin/submissions")
def admin_submissions(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    rows = db.execute(select(Submission.created_at, Participant.username, Submission.challenge_id, Submission.outcome).join(Participant, Participant.id == Submission.participant_id).order_by(Submission.id.desc()).limit(200)).all()
    return [{"time": r[0].isoformat(), "username": r[1], "challenge": r[2], "outcome": r[3]} for r in rows]


@app.get("/api/admin/audit")
def admin_audit(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(200)).all()
    return [{"time": r.created_at.isoformat(), "action": r.action, "role": r.actor_role, "target": r.target, "detail": r.detail} for r in rows]


@app.get("/api/admin/challenges")
def admin_challenges(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    counts = dict(db.execute(select(Solve.challenge_id, func.count()).group_by(Solve.challenge_id)).all())
    maps = {m.challenge_id: m.lab_id for m in db.scalars(select(LabMapping))}
    return [{"id": c.id, "title": c.title, "category": c.category, "points": c.points, "enabled": c.enabled, "visible": c.visible, "solves": counts.get(c.id, 0), "lab_id": maps.get(c.id)} for c in db.scalars(select(Challenge).order_by(Challenge.position))]


class ChallengePatch(BaseModel):
    points: int | None = Field(default=None, ge=0, le=10000)
    enabled: bool | None = None
    visible: bool | None = None


@app.patch("/api/admin/challenges/{cid}")
def admin_patch_challenge(cid: str, body: ChallengePatch, request: Request, o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    c = db.get(Challenge, cid)
    if not c:
        raise HTTPException(404, "Not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(c, k, v)
    services.audit(db, "challenge.update", o.id, "organizer", cid, body.model_dump(exclude_none=True), client_ip(request))
    db.commit()
    cache.clear()
    return {"ok": True}


class FlagAction(BaseModel):
    username: str
    challenge_id: str
    action: str = Field(pattern="^(rotate|revoke)$")


@app.post("/api/admin/flags")
def admin_flag_action(body: FlagAction, request: Request, o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    p = db.scalar(select(Participant).where(Participant.username_norm == security.normalize_username(body.username), Participant.role == "participant"))
    if not p or not db.get(Challenge, body.challenge_id):
        raise HTTPException(404, "Not found")
    (services.rotate_flag if body.action == "rotate" else services.revoke_flag)(db, p.id, body.challenge_id)
    services.audit(db, "flag." + body.action, o.id, "organizer", f"{p.username}:{body.challenge_id}", ip=client_ip(request))
    db.commit()
    return {"ok": True}


@app.post("/api/admin/participants/{pid}/status")
def admin_participant_status(pid: uuid.UUID, body: dict, request: Request, o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    status = body.get("status")
    p = db.get(Participant, pid)
    if status not in ("active", "disabled") or not p or p.role != "participant":
        raise HTTPException(404, "Not found")
    p.status = status
    if status == "disabled":
        services.revoke_all(db, p.id)
    services.audit(db, "participant." + status, o.id, "organizer", p.username, ip=client_ip(request))
    db.commit()
    cache.clear()
    return {"ok": True}


@app.get("/api/admin/export.csv")
def admin_export(o: Principal = Depends(require_organizer), db: Session = Depends(get_db)):
    rows = db.execute(select(Participant.username, func.coalesce(Score.total, 0), func.coalesce(Score.solved, 0), Score.last_solve_at).outerjoin(Score, Score.participant_id == Participant.id).where(Participant.role == "participant").order_by(Score.total.desc().nullslast())).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["username", "score", "solved", "last_solve_at"])
    for r in rows:
        w.writerow([("'" + r[0]) if r[0][:1] in "=+-@" else r[0], r[1], r[2], r[3].isoformat() if r[3] else ""])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=scores.csv"})


@app.get("/.well-known/jwks.json")
def jwks():
    return sso.jwks()


@app.get("/sso/authorize")
def sso_authorize(client_id: str, redirect_uri: str, state: str = "", p: Principal | None = Depends(principal_optional)):
    if not sso.redirect_allowed(client_id, redirect_uri):
        raise HTTPException(400, "Invalid client or redirect_uri")
    if not p or p.role != "participant":
        nxt = "/sso/authorize?" + urlencode({"client_id": client_id, "redirect_uri": redirect_uri, "state": state})
        return RedirectResponse("/?" + urlencode({"next": nxt}) + "#login", status_code=302)
    code = sso.make_code(p.id, p.sid, client_id, redirect_uri)
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(redirect_uri + sep + urlencode({"code": code, "state": state}), status_code=302)


class ExchangeIn(BaseModel):
    code: str = Field(max_length=200)
    client_id: str = Field(max_length=64)
    redirect_uri: str = Field(max_length=500)


@app.post("/internal/sso/exchange")
def sso_exchange(body: ExchangeIn, _=Depends(require_service), db: Session = Depends(get_db)):
    data = sso.consume_code(body.code, body.client_id)
    if not data or data["r"] != body.redirect_uri:
        raise HTTPException(400, "Invalid code")
    p = db.get(Participant, uuid.UUID(data["p"]))
    s = db.get(AuthSession, data["s"])
    if not p or p.status != "active" or p.role != "participant" or not s or s.revoked_at is not None or s.expires_at <= now():
        raise HTTPException(400, "Invalid code")
    return {"assertion": sso.make_assertion(p, data["s"], body.client_id), "participant_id": str(p.id), "username": p.username}


class SidIn(BaseModel):
    sid: str = Field(max_length=64)


@app.post("/internal/identity/introspect")
def introspect(body: SidIn, _=Depends(require_service), db: Session = Depends(get_db)):
    row = db.execute(select(Participant, AuthSession).join(AuthSession, AuthSession.participant_id == Participant.id).where(AuthSession.sid == body.sid)).first()
    if not row:
        return {"active": False}
    p, s = row
    active = p.status == "active" and p.role == "participant" and s.revoked_at is None and s.expires_at > now()
    return {"active": active, "participant_id": str(p.id), "username": p.username} if active else {"active": False}


@app.get("/internal/identity/{pid}")
def identity(pid: uuid.UUID, _=Depends(require_service), db: Session = Depends(get_db)):
    p = db.get(Participant, pid)
    if not p or p.role != "participant":
        raise HTTPException(404, "Not found")
    return {"id": str(p.id), "username": p.username, "status": p.status}


class ObjectiveIn(BaseModel):
    participant_id: uuid.UUID
    lab_id: str = Field(max_length=32)


@app.post("/internal/objectives")
def objective(body: ObjectiveIn, _=Depends(require_service), db: Session = Depends(get_db)):
    if store.incr(f"rl:issue:{body.participant_id}", 60) > config.ISSUE_LIMIT:
        raise HTTPException(429, "Too many requests")
    flag, status = services.issue_flag(db, body.participant_id, body.lab_id)
    if not flag:
        raise HTTPException(409 if status in ("revoked", "challenge_disabled") else 404, status)
    return {"flag": flag, "status": status}


@app.get("/internal/challenges")
def internal_challenges(_=Depends(require_service), db: Session = Depends(get_db)):
    maps = {m.challenge_id: m for m in db.scalars(select(LabMapping))}
    return [{"id": c.id, "lab_id": maps[c.id].lab_id if c.id in maps else None, "title": c.title, "points": c.points, "enabled": c.enabled and (maps[c.id].enabled if c.id in maps else True)} for c in db.scalars(select(Challenge).order_by(Challenge.position))]


@app.get("/internal/progress/{pid}")
def internal_progress(pid: uuid.UUID, _=Depends(require_service), db: Session = Depends(get_db)):
    solved = [r[0] for r in db.execute(select(Solve.challenge_id).where(Solve.participant_id == pid))]
    sc = db.get(Score, pid)
    return {"solved": solved, "score": sc.total if sc else 0}


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC), name="static")
