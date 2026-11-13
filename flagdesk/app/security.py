import base64
import hashlib
import hmac
import re
import secrets
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app import config

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
_dummy = _hasher.hash("dummy-password-for-timing")


def hash_password(password):
    return _hasher.hash(password)


def verify_password(password, stored):
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_password_check(password):
    verify_password(password, _dummy)


def normalize_username(name):
    return unicodedata.normalize("NFKC", name).strip().lower()


def hkdf(label, length=32):
    secret = config.FLAG_SECRET.encode()
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label.encode()).derive(secret)


def _session_key():
    base = (config.SESSION_SECRET or config.FLAG_SECRET).encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"flagdesk-session-v1").derive(base)


def _fernet():
    raw = (config.TOTP_ENC_KEY or config.FLAG_SECRET).encode()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"flagdesk-totp-v1").derive(raw)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(value):
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value):
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return None


def verify_totp(enc_secret, code):
    secret = decrypt_secret(enc_secret) if enc_secret else None
    if not secret or not re.fullmatch(r"\d{6}", code or ""):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def new_totp_secret():
    return pyotp.random_base32()


def make_session(participant_id, role, sid, hours):
    now = int(time.time())
    claims = {
        "iss": config.SSO_ISSUER,
        "aud": config.SESSION_AUDIENCE,
        "sub": str(participant_id),
        "role": role,
        "sid": sid,
        "jti": secrets.token_hex(8),
        "iat": now,
        "exp": now + hours * 3600,
    }
    return jwt.encode(claims, _session_key(), algorithm="HS256")


def read_session(token):
    try:
        return jwt.decode(
            token,
            _session_key(),
            algorithms=["HS256"],
            audience=config.SESSION_AUDIENCE,
            issuer=config.SSO_ISSUER,
            options={"require": ["exp", "iat", "sub", "sid", "jti", "aud", "iss"]},
        )
    except jwt.PyJWTError:
        return None


def new_sid():
    return secrets.token_urlsafe(24)


def token_sha256(token):
    return hashlib.sha256(token.encode()).hexdigest()


def const_eq(a, b):
    return hmac.compare_digest(a.encode(), b.encode())
