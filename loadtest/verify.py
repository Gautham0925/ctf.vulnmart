import json
import os
import sys
from collections import Counter, defaultdict

import psycopg

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "flagdesk"))
os.environ.setdefault("DATABASE_URL", "postgresql://x:y@localhost/z")
os.environ["FLAG_SECRET"] = os.environ.get("VERIFY_FLAG_SECRET", "flag-secret-" + "a" * 40)
os.environ.setdefault("EVENT_ID", "vulnmart-ctf-2026")
from app import flags  # noqa: E402


def run(dsn, flag_log, event_id="vulnmart-ctf-2026"):
    out = {}
    with psycopg.connect(dsn) as c:
        out["duplicate_solves"] = c.execute("select count(*) from (select participant_id, challenge_id from flagdesk.solves group by 1,2 having count(*)>1) t").fetchone()[0]
        out["score_mismatch"] = c.execute("select count(*) from flagdesk.scores s left join (select participant_id, coalesce(sum(points),0) pts, count(*) n from flagdesk.solves group by 1) x on x.participant_id=s.participant_id where s.total <> coalesce(x.pts,0) or s.solved <> coalesce(x.n,0)").fetchone()[0]
        out["solves_without_score"] = c.execute("select count(*) from flagdesk.solves v left join flagdesk.scores s on s.participant_id=v.participant_id where s.participant_id is null").fetchone()[0]
        out["solves_total"] = c.execute("select count(*) from flagdesk.solves").fetchone()[0]
        out["participants"] = c.execute("select count(*) from identity.participants where role='participant'").fetchone()[0]
        out["issued_flags"] = c.execute("select count(*) from flagdesk.issued_flags").fetchone()[0]
        out["duplicate_flag_digests"] = c.execute("select count(*) from (select flag_digest from flagdesk.issued_flags group by 1 having count(*)>1) t").fetchone()[0]
        out["correct_submissions_vs_solves_gap"] = c.execute("select (select count(*) from flagdesk.submissions where correct) - (select count(*) from flagdesk.solves)").fetchone()[0]
        out["flags_in_vulnmart_schema"] = 0
        cols = c.execute("select table_name, column_name from information_schema.columns where table_schema='vulnmart' and data_type in ('character varying','text','json','jsonb')").fetchall()
        for t, col in cols:
            out["flags_in_vulnmart_schema"] += c.execute(f'select count(*) from vulnmart."{t}" where cast("{col}" as text) like %s', ("%VULN{%",)).fetchone()[0]
    seen = defaultdict(set)
    mismatch = 0
    total = 0
    if os.path.exists(flag_log):
        with open(flag_log) as fh:
            for line in fh:
                e = json.loads(line)
                total += 1
                seen[e["flag"]].add(e["pid"])
                if e["flag"] != flags.derive(event_id, e["pid"], e["lab"], 1):
                    mismatch += 1
    out["flags_observed"] = total
    out["flag_ownership_mismatch"] = mismatch
    out["flags_shared_between_participants"] = sum(1 for v in seen.values() if len(v) > 1)
    return out


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], sys.argv[2]), indent=1))
