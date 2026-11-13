import re
import threading
import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config, security
from app.db import get_db
from app.models import AuthSession, Participant, now

COOKIE = "fd_session"
_hash_sem = threading.BoundedSemaphore(config.HASH_CONCURRENCY)


@dataclass
class Principal:
    id: uuid.UUID
    username: str
    role: str
    sid: str


def hash_guard():
    return _hash_sem


def client_ip(request: Request):
    return request.client.host if request.client else "unknown"


def principal_optional(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    claims = security.read_session(token)
    if not claims:
        return None
    row = db.execute(
        select(Participant, AuthSession).join(AuthSession, AuthSession.participant_id == Participant.id).where(AuthSession.sid == claims["sid"], Participant.id == uuid.UUID(claims["sub"]))
    ).first()
    if not row:
        return None
    p, s = row
    if p.status != "active" or s.revoked_at is not None or s.expires_at <= now():
        return None
    return Principal(p.id, p.username, p.role, s.sid)


def csrf(request: Request):
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-fd") != "1":
        raise HTTPException(403, "Missing CSRF header")


def require_principal(request: Request, p=Depends(principal_optional)):
    csrf(request)
    if not p:
        raise HTTPException(401, "Not signed in")
    return p


def require_participant(p: Principal = Depends(require_principal)):
    if p.role != "participant":
        raise HTTPException(403, "Participants only")
    return p


def require_organizer(p: Principal = Depends(require_principal)):
    if p.role != "organizer":
        raise HTTPException(404, "Not found")
    return p


def require_service(request: Request):
    header = request.headers.get("authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    if not config.SERVICE_TOKEN_SHA256 or not token or not security.const_eq(security.token_sha256(token), config.SERVICE_TOKEN_SHA256.lower()):
        raise HTTPException(401, "Service authentication failed")
    return True
