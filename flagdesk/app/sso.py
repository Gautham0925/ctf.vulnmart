import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import config, store

_key = None
_lock_path = None


def _load_or_create():
    if config.SSO_PRIVATE_KEY_PEM:
        return serialization.load_pem_private_key(config.SSO_PRIVATE_KEY_PEM.replace("\\n", "\n").encode(), password=None)
    path = config.SSO_PRIVATE_KEY_FILE or os.path.join(os.path.dirname(__file__), "..", "data", "sso_key.pem")
    if config.PRODUCTION and not os.path.exists(path):
        raise RuntimeError("SSO signing key missing in production (set SSO_PRIVATE_KEY_PEM or SSO_PRIVATE_KEY_FILE)")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        except FileExistsError:
            pass
    for _ in range(50):
        with open(path, "rb") as fh:
            data = fh.read()
        if data:
            return serialization.load_pem_private_key(data, password=None)
        time.sleep(0.05)
    raise RuntimeError("could not load SSO key")


def private_key():
    global _key
    if _key is None:
        _key = _load_or_create()
    return _key


def _b64(n):
    return base64.urlsafe_b64encode(n).rstrip(b"=").decode()


def jwk():
    nums = private_key().public_key().public_numbers()
    x, y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
    kid = hashlib.sha256(x + y).hexdigest()[:16]
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid, "x": _b64(x), "y": _b64(y)}


def jwks():
    return {"keys": [jwk()]}


def client(client_id):
    return config.SSO_CLIENTS.get(client_id)


def redirect_allowed(client_id, redirect_uri):
    c = client(client_id)
    return bool(c) and redirect_uri in c["redirect_uris"]


def make_code(participant_id, sid, client_id, redirect_uri):
    code = secrets.token_urlsafe(32)
    store.set_ex("sso:code:" + hashlib.sha256(code.encode()).hexdigest(), json.dumps({"p": str(participant_id), "s": sid, "c": client_id, "r": redirect_uri}), 60)
    return code


def consume_code(code, client_id):
    raw = store.getdel("sso:code:" + hashlib.sha256(code.encode()).hexdigest())
    if not raw:
        return None
    data = json.loads(raw)
    if data["c"] != client_id:
        return None
    return data


def make_assertion(participant, sid, client_id):
    c = client(client_id)
    now = int(time.time())
    claims = {
        "iss": config.SSO_ISSUER,
        "aud": c["audience"],
        "sub": str(participant.id),
        "preferred_username": participant.username,
        "role": participant.role,
        "sid": sid,
        "jti": secrets.token_hex(12),
        "iat": now,
        "exp": now + config.ASSERTION_MINUTES * 60,
    }
    return jwt.encode(claims, private_key(), algorithm="ES256", headers={"kid": jwk()["kid"]})


def verify_assertion(token, audience):
    key = jwt.PyJWK(jwk()).key
    return jwt.decode(token, key, algorithms=["ES256"], audience=audience, issuer=config.SSO_ISSUER, options={"require": ["exp", "iat", "sub", "sid", "jti", "aud", "iss"]})
