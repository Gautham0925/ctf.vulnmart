import threading
import time

import httpx
import jwt

from app.core.config import get_settings

settings = get_settings()
_client = None
_lock = threading.Lock()
_jwks = {"at": 0.0, "keys": {}}
_flag_cache = {}
_sid_cache = {}


def enabled() -> bool:
    return settings.ctf_enabled and bool(settings.flagdesk_service_token)


def _http() -> httpx.Client:
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = httpx.Client(
                    base_url=settings.flagdesk_internal_url.rstrip("/"),
                    timeout=httpx.Timeout(settings.ctf_timeout_seconds, connect=1.0),
                    limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
                    headers={"Authorization": f"Bearer {settings.flagdesk_service_token}"},
                )
    return _client


def _call(method, path, **kw):
    last = None
    for attempt in range(2):
        try:
            r = _http().request(method, path, **kw)
            if r.status_code >= 500 and attempt == 0:
                continue
            return r
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            last = exc
            time.sleep(0.05)
    raise last


def exchange_code(code: str, redirect_uri: str):
    r = _call("POST", "/internal/sso/exchange", json={"code": code, "client_id": settings.sso_client_id, "redirect_uri": redirect_uri})
    if r.status_code != 200:
        return None
    return r.json()


def _load_jwks(force=False):
    now = time.time()
    if not force and _jwks["keys"] and now - _jwks["at"] < 600:
        return
    r = _call("GET", "/.well-known/jwks.json")
    r.raise_for_status()
    _jwks["keys"] = {k["kid"]: jwt.PyJWK(k).key for k in r.json()["keys"]}
    _jwks["at"] = now


def verify_assertion(token: str) -> dict | None:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        _load_jwks()
        if kid not in _jwks["keys"]:
            _load_jwks(force=True)
        key = _jwks["keys"].get(kid)
        if key is None:
            return None
        return jwt.decode(token, key, algorithms=["ES256"], audience=settings.sso_audience, issuer=settings.sso_issuer, options={"require": ["exp", "iat", "sub", "sid", "jti", "aud", "iss"]})
    except (jwt.PyJWTError, httpx.HTTPError):
        return None


def session_active(sid: str, ttl: float = 10.0) -> bool:
    now = time.time()
    hit = _sid_cache.get(sid)
    if hit and hit[0] > now:
        return hit[1]
    try:
        r = _call("POST", "/internal/identity/introspect", json={"sid": sid})
        active = r.status_code == 200 and bool(r.json().get("active"))
    except httpx.HTTPError:
        return bool(hit and hit[1])
    if len(_sid_cache) > 5000:
        _sid_cache.clear()
    _sid_cache[sid] = (now + ttl, active)
    return active


def drop_session_cache(sid: str):
    _sid_cache.pop(sid, None)


def issue_flag(participant_id: str, lab_id: str) -> str | None:
    key = (participant_id, lab_id)
    now = time.time()
    hit = _flag_cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    try:
        r = _call("POST", "/internal/objectives", json={"participant_id": participant_id, "lab_id": lab_id})
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    flag = r.json().get("flag")
    if len(_flag_cache) > 5000:
        _flag_cache.clear()
    _flag_cache[key] = (now + 8, flag)
    return flag


def clear_caches():
    _flag_cache.clear()
    _sid_cache.clear()
    _jwks.update({"at": 0.0, "keys": {}})
