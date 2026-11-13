import time

import jwt
from fastapi import Request

from app.core.config import get_settings
from app.integration import flagdesk

settings = get_settings()
COOKIE = "vm_sso"
AUDIENCE = "vulnmart-shop-session"
NOTICE = "Sign in with your CTF account to receive your personal flag."


def _key() -> str:
    if not settings.shop_session_secret or len(settings.shop_session_secret) < 32:
        raise RuntimeError("SHOP_SESSION_SECRET (>=32 chars) is required")
    return settings.shop_session_secret


def make_cookie(participant_id: str, username: str, sid: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": "vulnmart-shop", "aud": AUDIENCE, "sub": participant_id, "preferred_username": username, "sid": sid, "iat": now, "exp": now + settings.shop_session_hours * 3600},
        _key(), algorithm="HS256",
    )


def read_cookie(token: str | None):
    if not token:
        return None
    try:
        return jwt.decode(token, _key(), algorithms=["HS256"], audience=AUDIENCE, issuer="vulnmart-shop", options={"require": ["exp", "iat", "sub", "sid", "aud", "iss"]})
    except (jwt.PyJWTError, RuntimeError):
        return None


def current(request: Request):
    claims = read_cookie(request.cookies.get(COOKIE))
    if not claims:
        return None
    if flagdesk.enabled() and not flagdesk.session_active(claims["sid"]):
        return None
    return claims


def flag_for_request(request: Request, lab_id: str) -> str:
    claims = current(request)
    if not claims:
        return NOTICE
    return flagdesk.issue_flag(claims["sub"], lab_id) or "Flag service unavailable. Try again shortly."
