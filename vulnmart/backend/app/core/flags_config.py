import hashlib
import hmac

from fastapi import HTTPException

from app.core.config import get_settings

LAB_IDS = tuple(f"LAB-{i:02d}" for i in range(1, 13))
MARK = "[[VMS:"


def sentinel(lab_id: str) -> str:
    key = (get_settings().shop_session_secret or "unset-sentinel-key").encode()
    return f"{MARK}{lab_id}:{hmac.new(key, lab_id.encode(), hashlib.sha256).hexdigest()[:12]}]]"


def reject_marker(*values: str) -> None:
    for v in values:
        if v and MARK in v:
            raise HTTPException(422, "Invalid characters in text")
