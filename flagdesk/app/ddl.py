from sqlalchemy import text

from app.db import Base
from app import models

TRIGGER = """
create or replace function identity.limit_organizers() returns trigger as $$
begin
  if new.role = 'organizer' and (select count(*) from identity.participants where role = 'organizer' and id <> new.id) >= 2 then
    raise exception 'at most two organizer accounts are allowed';
  end if;
  return new;
end $$ language plpgsql;
drop trigger if exists trg_limit_organizers on identity.participants;
create trigger trg_limit_organizers before insert or update on identity.participants for each row execute function identity.limit_organizers();
"""


def create_all(engine):
    with engine.begin() as conn:
        for s in ("identity", "flagdesk", "audit"):
            conn.execute(text(f"create schema if not exists {s}"))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text(TRIGGER))
