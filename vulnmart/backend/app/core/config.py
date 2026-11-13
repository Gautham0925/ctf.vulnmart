from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "training"
    app_mode: str = "training"
    training_ack: bool = True
    database_url: str = "postgresql+psycopg://vulnmarket:vulnmarket_local@localhost:5432/vulnmarket"
    redis_url: str = "redis://localhost:6379/0"
    keys_dir: str = "./keys"
    jwt_issuer: str = "https://vulnmarket.local"
    jwt_audience: str = "vulnmarket-web"
    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 604800
    partial_ttl_seconds: int = 300
    otp_ttl_seconds: int = 300
    ctf_enabled: bool = False
    seed_on_start: bool = True
    flagdesk_internal_url: str = "http://flagdesk:8000"
    flagdesk_public_url: str = "http://ctf.localhost:8081"
    flagdesk_service_token: str = ""
    sso_client_id: str = "vulnmart-shop"
    sso_audience: str = "vulnmart-shop"
    sso_issuer: str = "https://ctf.local"
    shop_public_url: str = "http://shop.localhost:8081"
    shop_session_secret: str = ""
    shop_session_hours: int = 12
    cookie_secure: bool = False
    local_registration_enabled: bool = True
    ctf_timeout_seconds: float = 2.5
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout: int = 10
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    static_dir: str = "./static"

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        for prefix in ("postgres://", "postgresql://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix):]
        return url

    @property
    def training_allowed(self) -> bool:
        return self.environment in ("local", "training", "development") and self.training_ack


@lru_cache
def get_settings() -> Settings:
    return Settings()
