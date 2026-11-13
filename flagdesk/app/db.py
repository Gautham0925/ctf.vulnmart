from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app import config

engine = create_engine(
    config.DATABASE_URL,
    pool_size=config.POOL_SIZE,
    max_overflow=config.POOL_OVERFLOW,
    pool_timeout=config.POOL_TIMEOUT,
    pool_pre_ping=True,
    pool_recycle=1800,
    connect_args={"prepare_threshold": None},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base(metadata=MetaData())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
