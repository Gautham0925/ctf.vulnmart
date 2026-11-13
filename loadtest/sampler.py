import csv
import subprocess
import threading
import time

import psutil
import psycopg


class Sampler(threading.Thread):
    def __init__(self, path, admin_dsn, interval=2.0):
        super().__init__(daemon=True)
        self.path, self.dsn, self.interval = path, admin_dsn, interval
        self.stop_ev = threading.Event()
        self.rows = []

    def groups(self):
        g = {"uvicorn": [], "postgres": [], "redis": [], "pgbouncer": [], "locust": []}
        for p in psutil.process_iter(["name", "cmdline"]):
            try:
                name = p.info["name"] or ""
                cmd = " ".join(p.info["cmdline"] or [])
                if "uvicorn" in cmd or "multiprocessing" in cmd and "spawn" in cmd:
                    g["uvicorn"].append(p)
                elif name.startswith("postgres"):
                    g["postgres"].append(p)
                elif name.startswith("redis"):
                    g["redis"].append(p)
                elif "pgbouncer" in name:
                    g["pgbouncer"].append(p)
                elif "locust" in cmd:
                    g["locust"].append(p)
            except psutil.Error:
                pass
        return g

    def run(self):
        conn = psycopg.connect(self.dsn, autocommit=True)
        procs = self.groups()
        for lst in procs.values():
            for p in lst:
                try:
                    p.cpu_percent(None)
                except psutil.Error:
                    pass
        with open(self.path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["t", "sys_cpu", "sys_mem_used_mb", "uvicorn_cpu", "uvicorn_rss_mb", "postgres_cpu", "postgres_rss_mb", "redis_cpu", "locust_cpu", "db_conns_total", "db_conns_flagdesk", "db_conns_vulnmart", "db_conns_active", "redis_clients"])
            t0 = time.time()
            while not self.stop_ev.wait(self.interval):
                procs = self.groups()
                def cpu(lst):
                    s = 0.0
                    for p in lst:
                        try:
                            s += p.cpu_percent(None)
                        except psutil.Error:
                            pass
                    return s
                def rss(lst):
                    s = 0
                    for p in lst:
                        try:
                            s += p.memory_info().rss
                        except psutil.Error:
                            pass
                    return s / 1048576
                try:
                    rows = conn.execute("select usename, state from pg_stat_activity where datname=%s", ("ctf_dev",)).fetchall()
                except Exception:
                    rows = []
                total = len(rows)
                fd = sum(1 for u, _ in rows if u == "flagdesk_app")
                vm = sum(1 for u, _ in rows if u == "vulnmart_app")
                act = sum(1 for _, s in rows if s == "active")
                try:
                    rc = int(subprocess.run(["redis-cli", "info", "clients"], capture_output=True, text=True, timeout=2).stdout.split("connected_clients:")[1].split()[0])
                except Exception:
                    rc = 0
                row = [round(time.time() - t0, 1), psutil.cpu_percent(None), round(psutil.virtual_memory().used / 1048576), round(cpu(procs["uvicorn"]), 1), round(rss(procs["uvicorn"])), round(cpu(procs["postgres"]), 1), round(rss(procs["postgres"])), round(cpu(procs["redis"]), 1), round(cpu(procs["locust"]), 1), total, fd, vm, act, rc]
                w.writerow(row)
                fh.flush()
                self.rows.append(row)

    def stop(self):
        self.stop_ev.set()
        self.join(5)
