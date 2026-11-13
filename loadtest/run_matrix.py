import argparse
import csv
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, HERE)
import dev_stack  # noqa: E402
import psycopg  # noqa: E402
import verify  # noqa: E402
from sampler import Sampler  # noqa: E402

ADMIN = os.environ.get("ADMIN_DSN", "postgresql://postgres:postgres@localhost:5432/ctf_dev")
SCENARIOS = {
    "users150_combined": dict(cls="CombinedUser", users=150, rate=15, desc="150 users, combined workload"),
    "vulnmart150": dict(cls="VulnMartOnlyUser", users=150, rate=15, desc="150 users on VulnMart"),
    "flagdesk150": dict(cls="FlagDeskOnlyUser", users=150, rate=15, desc="150 users on FlagDesk"),
    "submit50": dict(cls="SubmissionBurstUser", users=50, rate=50, desc="50 concurrent flag submissions", env={"BURST_USERS": "50"}),
    "leaderboard100": dict(cls="LeaderboardUser", users=100, rate=25, desc="100 concurrent leaderboard viewers"),
    "sustained30m": dict(cls="CombinedUser", users=150, rate=15, desc="150 users sustained", duration=1800),
}


def reset_state():
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute("delete from identity.participants where role='participant'")
        c.execute("truncate audit.audit_events, audit.objective_events")
        c.execute("delete from vulnmart.users where identity_uuid is not null and id not in (select user_id from vulnmart.addresses where false)") if False else None
    subprocess.run(["redis-cli", "flushall"], capture_output=True)


def read_stats(path):
    rows = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            rows.append(r)
    return rows


def pctl(r, key):
    try:
        return float(r[key])
    except Exception:
        return None


def run_scenario(name, cfg, out_root, duration, workers_fd, workers_vm):
    out = os.path.join(out_root, name)
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    procs = dev_stack.start(workers_fd, workers_vm)
    try:
        reset_state()
        flag_log = os.path.join(out, "flags_seen.jsonl")
        env = {**os.environ, "FD_URL": dev_stack.FD_URL, "VM_URL": dev_stack.VM_URL, "FLAG_LOG": flag_log, **cfg.get("env", {})}
        sampler = Sampler(os.path.join(out, "resources.csv"), ADMIN)
        sampler.start()
        dur = cfg.get("duration", duration)
        cmd = [sys.executable, "-m", "locust", "-f", os.path.join(HERE, "locustfile.py"), cfg["cls"], "--headless", "-u", str(cfg["users"]), "-r", str(cfg["rate"]), "-t", f"{dur}s", "--csv", os.path.join(out, "locust"), "--csv-full-history", "--only-summary"]
        t0 = time.time()
        subprocess.run(cmd, env=env, cwd=HERE, stdout=open(os.path.join(out, "locust.log"), "w"), stderr=subprocess.STDOUT)
        elapsed = time.time() - t0
        sampler.stop()
        v = verify.run(ADMIN, flag_log)
    finally:
        dev_stack.stop(procs)
    stats = read_stats(os.path.join(out, "locust_stats.csv"))
    summary = {"scenario": name, "description": cfg["desc"], "users": cfg["users"], "duration_s": round(elapsed), "workers_flagdesk": workers_fd, "workers_vulnmart": workers_vm, "stats": [{k: r[k] for k in ("Name", "Request Count", "Failure Count", "Median Response Time", "Average Response Time", "95%", "99%", "Max Response Time", "Requests/s")} for r in stats], "verify": v}
    res = [r for r in sampler.rows]
    if res:
        cols = ["t", "sys_cpu", "sys_mem_used_mb", "uvicorn_cpu", "uvicorn_rss_mb", "postgres_cpu", "postgres_rss_mb", "redis_cpu", "locust_cpu", "db_conns_total", "db_conns_flagdesk", "db_conns_vulnmart", "db_conns_active", "redis_clients"]
        summary["resources"] = {c: max(r[i] for r in res) for i, c in enumerate(cols) if c != "t"}
        summary["resources_avg_cpu"] = round(sum(r[1] for r in res) / len(res), 1)
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="*", default=list(SCENARIOS))
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--out", default=os.path.join(HERE, "..", "reports"))
    ap.add_argument("--users", type=int, default=0)
    ap.add_argument("--workers-flagdesk", type=int, default=2)
    ap.add_argument("--workers-vulnmart", type=int, default=2)
    a = ap.parse_args()
    for name in a.scenarios:
        cfg = dict(SCENARIOS[name])
        if a.users:
            cfg["users"] = a.users
            if "env" in cfg:
                cfg["env"] = {"BURST_USERS": str(a.users)}
        s = run_scenario(name, cfg, a.out, a.duration, a.workers_flagdesk, a.workers_vulnmart)
        agg = [r for r in s["stats"] if r["Name"] == "Aggregated"]
        print(name, "done", agg[0]["Request Count"] if agg else "?", "reqs", agg[0]["Failure Count"] if agg else "?", "fails", s["verify"], flush=True)
