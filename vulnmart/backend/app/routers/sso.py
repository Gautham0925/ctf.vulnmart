import hmac
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import get_db
from app.deps import client_ip
from app.integration import flagdesk, participant
from app.models import Cart, User
from app.routers.auth import full_tokens, new_session

router = APIRouter(prefix="/api/sso", tags=["sso"])
settings = get_settings()
STATE_COOKIE = "vm_sso_state"
UNUSABLE = "!sso-only"


def redirect_uri() -> str:
    return settings.shop_public_url.rstrip("/") + "/api/sso/callback"


def _cookie(response, name, value, max_age, path="/"):
    response.set_cookie(name, value, max_age=max_age, httponly=True, secure=settings.cookie_secure, samesite="lax", path=path)


@router.get("/login")
def sso_login():
    state = secrets.token_urlsafe(24)
    target = settings.flagdesk_public_url.rstrip("/") + "/sso/authorize?" + urlencode({"client_id": settings.sso_client_id, "redirect_uri": redirect_uri(), "state": state})
    response = RedirectResponse(target, status_code=302)
    _cookie(response, STATE_COOKIE, state, 600, "/api/sso")
    return response


def provision(db: Session, participant_id: str, username: str) -> User:
    user = db.query(User).filter(User.identity_uuid == participant_id).first()
    if user:
        return user
    user = User(username=username, email=f"{participant_id}@sso.invalid", full_name=username, password_hash=UNUSABLE, role="customer", identity_uuid=participant_id)
    db.add(user)
    try:
        db.flush()
        db.add(Cart(user_id=user.id))
        db.commit()
    except IntegrityError:
        db.rollback()
        user = db.query(User).filter(User.identity_uuid == participant_id).first()
        if not user:
            raise HTTPException(409, "Could not provision this account")
    return user


@router.get("/callback")
def sso_callback(request: Request, code: str = "", state: str = "", db: Session = Depends(get_db)):
    expected = request.cookies.get(STATE_COOKIE, "")
    if not code or not state or not expected or not hmac.compare_digest(expected.encode(), state.encode()):
        raise HTTPException(400, "Invalid sign-in state. Start again from the shop.")
    try:
        data = flagdesk.exchange_code(code, redirect_uri())
    except httpx.HTTPError:
        raise HTTPException(503, "CTF identity service unavailable")
    if not data:
        raise HTTPException(400, "Sign-in code rejected. Start again.")
    claims = flagdesk.verify_assertion(data["assertion"])
    if not claims or claims.get("role") != "participant":
        raise HTTPException(400, "Sign-in assertion rejected")
    user = provision(db, claims["sub"], claims["preferred_username"])
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    response = RedirectResponse("/", status_code=302)
    _cookie(response, participant.COOKIE, participant.make_cookie(claims["sub"], claims["preferred_username"], claims["sid"]), settings.shop_session_hours * 3600)
    response.delete_cookie(STATE_COOKIE, path="/api/sso")
    return response


@router.get("/config")
def sso_config():
    return {"sso_enabled": settings.ctf_enabled, "local_registration": settings.local_registration_enabled, "flagdesk_url": settings.flagdesk_public_url}


@router.get("/me")
def sso_me(request: Request):
    ctx = participant.current(request)
    if not ctx:
        raise HTTPException(401, "Not signed in")
    return {"participant_id": ctx["sub"], "username": ctx["preferred_username"]}


@router.post("/session")
def sso_session(request: Request, db: Session = Depends(get_db)):
    if request.headers.get("x-vm") != "1":
        raise HTTPException(403, "Missing header")
    ctx = participant.current(request)
    if not ctx:
        raise HTTPException(401, "Not signed in")
    user = db.query(User).filter(User.identity_uuid == ctx["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(401, "Account unavailable")
    session = new_session(db, user, request, "authenticated")
    return full_tokens(db, user, session)


@router.post("/logout")
def sso_logout(request: Request, response: Response):
    if request.headers.get("x-vm") != "1":
        raise HTTPException(403, "Missing header")
    ctx = participant.read_cookie(request.cookies.get(participant.COOKIE))
    if ctx:
        flagdesk.drop_session_cache(ctx["sid"])
    response.delete_cookie(participant.COOKIE, path="/")
    return {"ok": True}
