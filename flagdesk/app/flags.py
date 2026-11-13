import hashlib
import hmac
import re
import uuid

from app import config
from app.security import hkdf

PREFIX = "VULN{"
SUFFIX = "}"
FLAG_RE = re.compile(r"^VULN\{[0-9A-F]{32}\}$")
_key_cache = {}


def _key():
    k = _key_cache.get(config.FLAG_SECRET)
    if k is None:
        if len(config.FLAG_SECRET) < 32:
            raise RuntimeError("FLAG_SECRET must be at least 32 characters")
        k = hkdf("flagdesk-flag-v1")
        _key_cache.clear()
        _key_cache[config.FLAG_SECRET] = k
    return k


def derive(event_id, participant_id, challenge_id, version):
    msg = "\0".join(("v1", event_id, str(uuid.UUID(str(participant_id))), challenge_id, str(int(version)))).encode()
    mac = hmac.new(_key(), msg, hashlib.sha256).hexdigest()[:32].upper()
    return f"{PREFIX}{mac}{SUFFIX}"


def well_formed(value):
    return bool(value) and bool(FLAG_RE.match(value))


def digest(flag):
    return hashlib.sha256(flag.encode()).hexdigest()


def matches(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
