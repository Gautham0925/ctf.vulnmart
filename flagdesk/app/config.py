import json
import os


def _bool(name, default):
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes")


def _int(name, default):
    return int(os.environ.get(name, str(default)))


def _database_url():
    raw = os.environ.get("DATABASE_URL", "").strip().strip("\"'").strip()
    if not raw:
        raise RuntimeError("DATABASE_URL is required (PostgreSQL)")
    if raw.startswith("postgres://"):
        raw = "postgresql+psycopg://" + raw[len("postgres://"):]
    elif raw.startswith("postgresql://"):
        raw = "postgresql+psycopg://" + raw[len("postgresql://"):]
    if not raw.startswith("postgresql+psycopg://"):
        raise RuntimeError("DATABASE_URL must be a PostgreSQL URL")
    return raw


ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
PRODUCTION = ENVIRONMENT == "production"
DATABASE_URL = _database_url()
REDIS_URL = os.environ.get("REDIS_URL", "")
EVENT_ID = os.environ.get("EVENT_ID", "vulnmart-ctf-2026")
EVENT_NAME = os.environ.get("EVENT_NAME", "VULNMART CTF")
FLAG_SECRET = os.environ.get("FLAG_SECRET", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
ORGANIZER_1 = os.environ.get("ORGANIZER_1_USERNAME", "")
ORGANIZER_1_PASSWORD = os.environ.get("ORGANIZER_1_PASSWORD", "")
ORGANIZER_1_TOTP = os.environ.get("ORGANIZER_1_TOTP_SECRET", "")
ORGANIZER_2 = os.environ.get("ORGANIZER_2_USERNAME", "")
ORGANIZER_2_PASSWORD = os.environ.get("ORGANIZER_2_PASSWORD", "")
ORGANIZER_2_TOTP = os.environ.get("ORGANIZER_2_TOTP_SECRET", "")
TOTP_ENC_KEY = os.environ.get("TOTP_ENC_KEY", "")
SSO_PRIVATE_KEY_PEM = os.environ.get("SSO_PRIVATE_KEY_PEM", "")
SSO_PRIVATE_KEY_FILE = os.environ.get("SSO_PRIVATE_KEY_FILE", "")
SSO_ISSUER = os.environ.get("SSO_ISSUER", "https://ctf.local")
SESSION_AUDIENCE = "flagdesk"
SSO_CLIENTS = json.loads(os.environ.get("SSO_CLIENTS", "{}")) or {
    "vulnmart-shop": {"redirect_uris": ["http://shop.localhost:8081/sso/callback"], "audience": "vulnmart-shop"}
}
SHOP_PUBLIC_URL = os.environ.get("SHOP_PUBLIC_URL", "http://shop.localhost:8081")
SHOP_INTERNAL_URL = os.environ.get("SHOP_INTERNAL_URL", "http://vulnmart:8000")
SERVICE_TOKEN_SHA256 = os.environ.get("VULNMART_SERVICE_TOKEN_SHA256", "")
SHOP_SERVICE_TOKEN = os.environ.get("SHOP_SERVICE_TOKEN", "")
PARTICIPANT_SESSION_HOURS = _int("SESSION_HOURS", 12)
ORGANIZER_SESSION_HOURS = _int("ORGANIZER_SESSION_HOURS", 2)
ASSERTION_MINUTES = _int("ASSERTION_MINUTES", 60)
COOKIE_SECURE = _bool("COOKIE_SECURE", PRODUCTION)
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", "") or None
REGISTRATION_OPEN = _bool("REGISTRATION_OPEN", True)
EVENT_CODE = os.environ.get("EVENT_CODE", "")
MAX_PARTICIPANTS = _int("MAX_PARTICIPANTS", 0)
WRONG_LIMIT = _int("WRONG_LIMIT", 8)
WRONG_WINDOW = _int("WRONG_WINDOW", 60)
LOGIN_LIMIT = _int("LOGIN_LIMIT", 10)
LOGIN_WINDOW = _int("LOGIN_WINDOW", 300)
IP_LOGIN_LIMIT = _int("IP_LOGIN_LIMIT", 600)
REGISTER_IP_LIMIT = _int("REGISTER_IP_LIMIT", 400)
ISSUE_LIMIT = _int("ISSUE_LIMIT", 120)
POOL_SIZE = _int("POOL_SIZE", 8)
POOL_OVERFLOW = _int("POOL_OVERFLOW", 8)
POOL_TIMEOUT = _int("POOL_TIMEOUT", 10)
HASH_CONCURRENCY = _int("HASH_CONCURRENCY", 4)
BOARD_TTL = float(os.environ.get("BOARD_TTL", "3"))
FLAG_CACHE_TTL = _int("FLAG_CACHE_TTL", 30)
AUTO_CREATE_TABLES = _bool("AUTO_CREATE_TABLES", False)
SEED_FILE = os.environ.get("SEED_FILE", os.path.join(os.path.dirname(__file__), "..", "challenges.seed.json"))
REQUIRE_ORGANIZERS = _bool("REQUIRE_ORGANIZERS", PRODUCTION)
RESERVED_EXTRA = [s.strip().lower() for s in os.environ.get("RESERVED_USERNAMES", "").split(",") if s.strip()]
