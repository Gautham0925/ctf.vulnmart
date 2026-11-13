import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "reports")
ORDER = ["users150_combined", "vulnmart150", "flagdesk150", "submit50", "leaderboard100", "sustained30m"]
FLAG_ENDPOINTS = ("FD submit flag", "FD burst submit")


def load(name):
    p = os.path.join(ROOT, name, "summary.json")
    return json.load(open(p)) if os.path.exists(p) else None


def f(v):
    try:
        return f"{float(v):.0f}"
    except Exception:
        return str(v)


def evaluate(s):
    rows = s["stats"]
    agg = next(r for r in rows if r["Name"] == "Aggregated")
    steady = [r for r in rows if r["Name"] != "Aggregated" and not r["Name"].startswith("setup:")]
    setup = [r for r in rows if r["Name"].startswith("setup:")]
    total = int(agg["Request Count"])
    fails = int(agg["Failure Count"])
    err = 100.0 * fails / total if total else 0.0
    worst95 = max((float(r["95%"]) for r in steady if int(r["Request Count"]) >= 20), default=0.0)
    worst_name = next((r["Name"] for r in steady if int(r["Request Count"]) >= 20 and float(r["95%"]) == worst95), "")
    flag95 = max((float(r["95%"]) for r in steady if r["Name"] in FLAG_ENDPOINTS), default=None)
    v = s["verify"]
    res = s.get("resources", {})
    checks = {
        "error rate < 1%": (err < 1.0, f"{err:.2f}% ({fails}/{total})"),
        "p95 < 500 ms (every steady-state endpoint)": (worst95 < 500, f"worst {worst95:.0f} ms ({worst_name})"),
        "flag validation p95 < 300 ms": (flag95 is None or flag95 < 300, "n/a" if flag95 is None else f"{flag95:.0f} ms"),
        "no duplicate solves": (v["duplicate_solves"] == 0 and v["duplicate_flag_digests"] == 0, f"{v['duplicate_solves']} duplicate solves, {v['duplicate_flag_digests']} duplicate digests"),
        "no lost / wrong scores": (v["score_mismatch"] == 0 and v["solves_without_score"] == 0 and v["correct_submissions_vs_solves_gap"] == 0, f"{v['score_mismatch']} mismatched, {v['correct_submissions_vs_solves_gap']} gap"),
        "no cross-participant flag leakage": (v["flag_ownership_mismatch"] == 0 and v["flags_shared_between_participants"] == 0 and v["flags_in_vulnmart_schema"] == 0, f"{v['flags_observed']} flags observed, {v['flag_ownership_mismatch']} wrong owner, {v['flags_shared_between_participants']} shared, {v['flags_in_vulnmart_schema']} stored in shop DB"),
        "no DB connection exhaustion": (res.get("db_conns_flagdesk", 0) <= 80 and res.get("db_conns_vulnmart", 0) <= 50 and not any(r["Name"] != "Aggregated" and False for r in rows), f"peak {res.get('db_conns_flagdesk', '?')} flagdesk_app / {res.get('db_conns_vulnmart', '?')} vulnmart_app connections (limits 80 / 50)"),
    }
    return agg, steady, setup, checks, err


def main():
    out = ["# Load test results", "", "> **Sandbox numbers.** These runs used a 2-vCPU / 8 GB sandbox that also hosted PostgreSQL, Redis, both applications (2 workers each) and the Locust generator.", "> CPU was the limiting resource. They show relative behaviour and correctness under concurrency; they are **not valid for production sizing**. Re-run the matrix on the real host (see docs/OPERATIONS.md).", ""]
    for name in ORDER:
        s = load(name)
        if not s:
            out += [f"## {name}", "", "_not run_", ""]
            continue
        agg, steady, setup, checks, err = evaluate(s)
        out += [f"## {s['description']} (`{name}`)", "", f"{s['users']} users, {s['duration_s']} s, workers FlagDesk/VulnMart = {s['workers_flagdesk']}/{s['workers_vulnmart']}. Total {agg['Request Count']} requests, {agg['Failure Count']} failures, {float(agg['Requests/s']):.1f} req/s.", "", "| Objective | Result | Measured |", "|---|---|---|"]
        for k, (ok, detail) in checks.items():
            out.append(f"| {k} | {'PASS' if ok else 'FAIL'} | {detail} |")
        out += ["", "| Endpoint | Requests | Fails | p50 ms | p95 ms | p99 ms | max ms | req/s |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for r in steady + setup:
            out.append(f"| {r['Name']} | {r['Request Count']} | {r['Failure Count']} | {f(r['Median Response Time'])} | {f(r['95%'])} | {f(r['99%'])} | {f(r['Max Response Time'])} | {float(r['Requests/s']):.1f} |")
        res = s.get("resources", {})
        if res:
            out += ["", f"Peak resources: system CPU {res['sys_cpu']:.0f}% (mean {s.get('resources_avg_cpu', '?')}%), app workers CPU {res['uvicorn_cpu']:.0f}% / RSS {res['uvicorn_rss_mb']:.0f} MB, PostgreSQL CPU {res['postgres_cpu']:.0f}% / RSS {res['postgres_rss_mb']:.0f} MB, Locust CPU {res['locust_cpu']:.0f}%, Redis clients {res['redis_clients']}.", f"Database connections (peak): total {res['db_conns_total']}, flagdesk_app {res['db_conns_flagdesk']}, vulnmart_app {res['db_conns_vulnmart']}, simultaneously active {res['db_conns_active']}."]
        v = s["verify"]
        out += ["", f"Post-run SQL checks: {v['solves_total']} solves for {v['participants']} participants, {v['issued_flags']} issued flags, duplicate solves {v['duplicate_solves']}, score/solve mismatches {v['score_mismatch']}.", ""]
    open(os.path.join(ROOT, "LOADTEST_RESULTS.md"), "w").write("\n".join(out))
    print("\n".join(out)[:3000])


if __name__ == "__main__":
    main()
