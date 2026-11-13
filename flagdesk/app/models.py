import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, LargeBinary, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def now():
    return datetime.now(timezone.utc)


TS = DateTime(timezone=True)


class Participant(Base):
    __tablename__ = "participants"
    __table_args__ = (
        CheckConstraint("role in ('participant','organizer')", name="ck_role"),
        CheckConstraint("status in ('active','disabled')", name="ck_status"),
        CheckConstraint("role <> 'organizer' or is_protected", name="ck_organizer_protected"),
        Index("ix_participants_role_status", "role", "status"),
        {"schema": "identity"},
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(32))
    username_norm: Mapped[str] = mapped_column(String(32), unique=True)
    role: Mapped[str] = mapped_column(String(16), default="participant")
    status: Mapped[str] = mapped_column(String(16), default="active")
    is_protected: Mapped[bool] = mapped_column(Boolean, default=False)
    pw_hash: Mapped[str] = mapped_column(String(255))
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class AuthSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_participant", "participant_id"), {"schema": "identity"})
    sid: Mapped[str] = mapped_column(String(48), primary_key=True)
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    ip: Mapped[str] = mapped_column(String(64), default="")


class ReservedUsername(Base):
    __tablename__ = "reserved_usernames"
    __table_args__ = {"schema": "identity"}
    username_norm: Mapped[str] = mapped_column(String(32), primary_key=True)
    reason: Mapped[str] = mapped_column(String(64), default="")


class Event(Base):
    __tablename__ = "events"
    __table_args__ = {"schema": "flagdesk"}
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Challenge(Base):
    __tablename__ = "challenges"
    __table_args__ = (CheckConstraint("points >= 0", name="ck_points"), {"schema": "flagdesk"})
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(40), default="Web")
    description: Mapped[str] = mapped_column(Text, default="")
    points: Mapped[int] = mapped_column(Integer, default=100)
    position: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)


class LabMapping(Base):
    __tablename__ = "lab_mappings"
    __table_args__ = (UniqueConstraint("challenge_id", name="uq_mapping_challenge"), {"schema": "flagdesk"})
    lab_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(32), ForeignKey("flagdesk.challenges.id", ondelete="CASCADE"))
    app: Mapped[str] = mapped_column(String(32), default="vulnmart")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class FlagState(Base):
    __tablename__ = "flag_state"
    __table_args__ = {"schema": "flagdesk"}
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"), primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(32), ForeignKey("flagdesk.challenges.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(TS, default=now)


class IssuedFlag(Base):
    __tablename__ = "issued_flags"
    __table_args__ = (
        UniqueConstraint("event_id", "participant_id", "challenge_id", "version", name="uq_issued_version"),
        {"schema": "flagdesk"},
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64))
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"))
    challenge_id: Mapped[str] = mapped_column(String(32), ForeignKey("flagdesk.challenges.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    flag_digest: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime] = mapped_column(TS, default=now)


class Solve(Base):
    __tablename__ = "solves"
    __table_args__ = (
        UniqueConstraint("participant_id", "challenge_id", name="uq_solve"),
        Index("ix_solves_challenge", "challenge_id"),
        {"schema": "flagdesk"},
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"))
    challenge_id: Mapped[str] = mapped_column(String(32), ForeignKey("flagdesk.challenges.id", ondelete="CASCADE"))
    points: Mapped[int] = mapped_column(Integer)
    solved_at: Mapped[datetime] = mapped_column(TS, default=now)


class Score(Base):
    __tablename__ = "scores"
    __table_args__ = (Index("ix_scores_rank", "total", "last_solve_at"), {"schema": "flagdesk"})
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"), primary_key=True)
    total: Mapped[int] = mapped_column(Integer, default=0)
    solved: Mapped[int] = mapped_column(Integer, default=0)
    last_solve_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class Submission(Base):
    __tablename__ = "submissions"
    __table_args__ = (Index("ix_sub_participant_time", "participant_id", "created_at"), {"schema": "flagdesk"})
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("identity.participants.id", ondelete="CASCADE"))
    challenge_id: Mapped[str] = mapped_column(String(32), ForeignKey("flagdesk.challenges.id", ondelete="CASCADE"))
    correct: Mapped[bool] = mapped_column(Boolean)
    outcome: Mapped[str] = mapped_column(String(24), default="")
    digest_prefix: Mapped[str] = mapped_column(String(12), default="")
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_time", "created_at"), Index("ix_audit_action", "action"), {"schema": "audit"})
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_role: Mapped[str] = mapped_column(String(16), default="")
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class ObjectiveEvent(Base):
    __tablename__ = "objective_events"
    __table_args__ = (Index("ix_obj_participant", "participant_id", "challenge_id"), {"schema": "audit"})
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    participant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    challenge_id: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(32), default="vulnmart")
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Announcement(Base):
    __tablename__ = "announcements"
    __table_args__ = (Index("ix_announcements_created", "created_at"), {"schema": "flagdesk"})
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(String(1000), default="")
    link: Mapped[str] = mapped_column(String(500), default="")
    challenge_id: Mapped[str] = mapped_column(String(32), default="")
    kind: Mapped[str] = mapped_column(String(16), default="message")
    sound: Mapped[str] = mapped_column(String(40), default="", server_default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = {"schema": "flagdesk"}
    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(300), default="")
    filename: Mapped[str] = mapped_column(String(80))
    content: Mapped[str] = mapped_column(Text)
    labs: Mapped[list] = mapped_column(JSONB, default=list)
    released_labs: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)
    released_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class Sound(Base):
    __tablename__ = "sounds"
    __table_args__ = {"schema": "flagdesk"}
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(60))
    mime: Mapped[str] = mapped_column(String(32))
    data: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(TS, default=now)


class Setting(Base):
    __tablename__ = "settings"
    __table_args__ = {"schema": "flagdesk"}
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[str] = mapped_column(String(200), default="")
