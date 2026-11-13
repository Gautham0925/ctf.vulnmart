import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import config, flags, security
from app.models import Announcement, AuditEvent, AuthSession, Challenge, Event, FlagState, IssuedFlag, LabMapping, ObjectiveEvent, Participant, Resource, ReservedUsername, Score, Solve, Submission, now

BASE_RESERVED = ["admin", "administrator", "organizer", "organiser", "root", "system", "support", "staff", "moderator", "flagdesk", "vulnmart", "vulnmarket", "ctf", "api", "null", "undefined"]
VULNMART_PERSONAS = ["admin", "ops.admin", "techhub", "stylehouse", "homenest", "pagebarn", "alice.morgan", "bob.carter", "carol.nguyen", "david.okafor", "erin.kowalski", "frank.silva", "grace.holt", "vault.audit", "ops.recovery"]


def audit(db, action, actor=None, role="", target="", detail=None, ip=""):
    db.add(AuditEvent(actor_id=actor, actor_role=role, action=action, target=target[:80], detail=detail or {}, ip=ip))


def seed_reserved(db):
    names = set(BASE_RESERVED + VULNMART_PERSONAS + config.RESERVED_EXTRA)
    for o in (config.ORGANIZER_1, config.ORGANIZER_2):
        if o:
            names.add(o)
    for n in names:
        db.execute(pg_insert(ReservedUsername).values(username_norm=security.normalize_username(n), reason="reserved").on_conflict_do_nothing())
    db.commit()


def seed_event_and_challenges(db):
    db.execute(pg_insert(Event).values(id=config.EVENT_ID, name=config.EVENT_NAME, active=True).on_conflict_do_nothing())
    if db.scalar(select(func.count()).select_from(Challenge)) == 0 and os.path.exists(config.SEED_FILE):
        with open(config.SEED_FILE, encoding="utf-8") as fh:
            items = json.load(fh)
        for i, c in enumerate(items):
            db.execute(pg_insert(Challenge).values(id=c["id"], title=c["title"], category=c.get("category", "Web"), description=c.get("description", ""), points=int(c.get("points", 100)), position=i, enabled=True, visible=True).on_conflict_do_nothing())
            db.execute(pg_insert(LabMapping).values(lab_id=c["id"], challenge_id=c["id"], app="vulnmart", enabled=True).on_conflict_do_nothing())
    db.commit()


def bootstrap_organizers(db):
    pairs = [(config.ORGANIZER_1, config.ORGANIZER_1_PASSWORD, config.ORGANIZER_1_TOTP), (config.ORGANIZER_2, config.ORGANIZER_2_PASSWORD, config.ORGANIZER_2_TOTP)]
    given = [p for p in pairs if p[0] and p[1] and p[2]]
    if config.REQUIRE_ORGANIZERS and len(given) != 2:
        raise RuntimeError("exactly two organizers must be provisioned via environment (ORGANIZER_n_USERNAME/PASSWORD/TOTP_SECRET)")
    if len({security.normalize_username(p[0]) for p in given}) != len(given):
        raise RuntimeError("organizer usernames must differ")
    for username, password, totp in given:
        norm = security.normalize_username(username)
        existing = db.scalar(select(Participant).where(Participant.username_norm == norm))
        if existing and existing.role != "organizer":
            raise RuntimeError("organizer username collides with an existing participant")
        if existing:
            existing.pw_hash = security.hash_password(password)
            existing.totp_secret_enc = security.encrypt_secret(totp)
            existing.status = "active"
        else:
            db.add(Participant(username=username, username_norm=norm, role="organizer", is_protected=True, pw_hash=security.hash_password(password), totp_secret_enc=security.encrypt_secret(totp)))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
    count = db.scalar(select(func.count()).select_from(Participant).where(Participant.role == "organizer"))
    if count > 2:
        raise RuntimeError("more than two organizer accounts exist")


def create_participant(db, username, password):
    norm = security.normalize_username(username)
    if db.scalar(select(ReservedUsername.username_norm).where(ReservedUsername.username_norm == norm)):
        return None
    p = Participant(username=username, username_norm=norm, role="participant", pw_hash=security.hash_password(password))
    db.add(p)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return None
    return p


def open_session(db, participant, ip):
    hours = config.ORGANIZER_SESSION_HOURS if participant.role == "organizer" else config.PARTICIPANT_SESSION_HOURS
    sid = security.new_sid()
    db.add(AuthSession(sid=sid, participant_id=participant.id, expires_at=now() + timedelta(hours=hours), ip=ip))
    participant.last_login_at = now()
    return sid, security.make_session(participant.id, participant.role, sid, hours)


def revoke_session(db, sid):
    db.execute(text("update identity.sessions set revoked_at = now() where sid = :s and revoked_at is null"), {"s": sid})


def revoke_all(db, participant_id):
    db.execute(text("update identity.sessions set revoked_at = now() where participant_id = :p and revoked_at is null"), {"p": participant_id})


def current_flag_state(db, participant_id, challenge_id):
    db.execute(pg_insert(FlagState).values(event_id=config.EVENT_ID, participant_id=participant_id, challenge_id=challenge_id).on_conflict_do_nothing())
    return db.get(FlagState, (config.EVENT_ID, participant_id, challenge_id))


def issue_flag(db, participant_id, lab_id):
    m = db.get(LabMapping, lab_id)
    if not m or not m.enabled:
        return None, "unknown_lab"
    ch = db.get(Challenge, m.challenge_id)
    if not ch or not ch.enabled:
        return None, "challenge_disabled"
    p = db.get(Participant, participant_id)
    if not p or p.role != "participant" or p.status != "active":
        return None, "not_eligible"
    st = current_flag_state(db, participant_id, ch.id)
    if st.revoked:
        return None, "revoked"
    flag = flags.derive(config.EVENT_ID, participant_id, ch.id, st.version)
    db.execute(pg_insert(IssuedFlag).values(event_id=config.EVENT_ID, participant_id=participant_id, challenge_id=ch.id, version=st.version, flag_digest=flags.digest(flag)).on_conflict_do_nothing())
    db.add(ObjectiveEvent(participant_id=participant_id, challenge_id=ch.id))
    db.commit()
    return flag, "ok"


def rotate_flag(db, participant_id, challenge_id):
    st = current_flag_state(db, participant_id, challenge_id)
    st.version += 1
    st.revoked = False
    st.updated_at = now()


def revoke_flag(db, participant_id, challenge_id):
    st = current_flag_state(db, participant_id, challenge_id)
    st.revoked = True
    st.updated_at = now()


def submit(db, participant_id, challenge_id, submitted):
    ch = db.get(Challenge, challenge_id)
    if not ch or not ch.enabled or not ch.visible:
        return {"status": "unknown"}
    if not flags.well_formed(submitted):
        db.add(Submission(participant_id=participant_id, challenge_id=challenge_id, correct=False, outcome="malformed"))
        db.commit()
        return {"status": "incorrect"}
    if db.scalar(select(Solve.id).where(Solve.participant_id == participant_id, Solve.challenge_id == challenge_id)):
        return {"status": "already_solved"}
    st = db.get(FlagState, (config.EVENT_ID, participant_id, challenge_id))
    ok = False
    if st and not st.revoked:
        expected = flags.derive(config.EVENT_ID, participant_id, challenge_id, st.version)
        issued = db.scalar(select(IssuedFlag.id).where(IssuedFlag.event_id == config.EVENT_ID, IssuedFlag.participant_id == participant_id, IssuedFlag.challenge_id == challenge_id, IssuedFlag.version == st.version))
        ok = flags.matches(submitted, expected) and issued is not None
    if not ok:
        owner = db.scalar(select(IssuedFlag.participant_id).where(IssuedFlag.flag_digest == flags.digest(submitted)))
        outcome = "foreign_flag" if owner and owner != participant_id else ("stale_or_revoked" if owner else "wrong")
        db.add(Submission(participant_id=participant_id, challenge_id=challenge_id, correct=False, outcome=outcome, digest_prefix=flags.digest(submitted)[:12]))
        if outcome == "foreign_flag":
            audit(db, "flag.foreign_submission", participant_id, "participant", challenge_id, {"owner": str(owner)})
        db.commit()
        return {"status": "incorrect"}
    row = db.execute(pg_insert(Solve).values(participant_id=participant_id, challenge_id=challenge_id, points=ch.points).on_conflict_do_nothing(index_elements=["participant_id", "challenge_id"]).returning(Solve.id)).first()
    if row is None:
        db.rollback()
        return {"status": "already_solved"}
    stmt = pg_insert(Score).values(participant_id=participant_id, total=ch.points, solved=1, last_solve_at=now())
    db.execute(stmt.on_conflict_do_update(index_elements=["participant_id"], set_={"total": Score.total + ch.points, "solved": Score.solved + 1, "last_solve_at": now()}))
    db.add(Submission(participant_id=participant_id, challenge_id=challenge_id, correct=True, outcome="solved"))
    db.commit()
    return {"status": "correct", "points": ch.points}


WORDLISTS = [
    ("usernames", "Usernames (enumeration)", "Candidate usernames for the login and password-reset enumeration labs.", "usernames.txt", ["LAB-01", "LAB-02"]),
    ("xss-reflected", "XSS payloads: reflected", "Payloads for the reflected XSS lab.", "xss-reflected.txt", ["LAB-07"]),
    ("xss-stored", "XSS payloads: stored", "Payloads for the stored XSS lab.", "xss-stored.txt", ["LAB-08"]),
    ("xss-dom", "XSS payloads: DOM-based", "Payloads for the DOM XSS lab (URL fragment).", "xss-dom.txt", ["LAB-09"]),
    ("sqli", "SQL injection payloads", "Probing and UNION payloads for the SQL injection lab.", "sqli.txt", ["LAB-10"]),
    ("ids-1-100", "Numeric IDs 1-100", "Sequential IDs for object-reference labs.", "ids-1-100.txt", ["LAB-03", "LAB-06"]),
    ("mass-assignment", "Profile field names", "Field names to try when updating a profile.", "mass-assignment-fields.txt", ["LAB-05"]),
    ("jwt-tests", "JWT header and claim tests", "Algorithm, key id and claim values to try.", "jwt-tests.txt", ["LAB-11"]),
    ("api-endpoints", "API paths", "Paths worth requesting while mapping the API.", "api-endpoints.txt", ["LAB-05", "LAB-11", "LAB-12"]),
]


def seed_wordlists(db):
    base = os.path.join(os.path.dirname(__file__), "..", "wordlists")
    for rid, title, desc, fname, labs in WORDLISTS:
        if db.get(Resource, rid):
            continue
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            db.add(Resource(id=rid, title=title, description=desc, filename=fname, content=fh.read(), labs=labs, released_labs=[]))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
