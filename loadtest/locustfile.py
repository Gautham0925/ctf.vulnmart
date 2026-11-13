import json
import os
import random
import re
import threading
import uuid

from locust import HttpUser, between, constant, events, task
from locust.clients import HttpSession

FD_HEADERS = {"x-fd": "1"}
VM_URL = os.environ.get("VM_URL", "http://localhost:8101")
FD_URL = os.environ.get("FD_URL", "http://127.0.0.1:8100")
FLAG_LOG = os.environ.get("FLAG_LOG", "reports/flags_seen.jsonl")
LABS = ["LAB-01", "LAB-02", "LAB-04", "LAB-12"]
PASSWORD = "Password-123"
_log_lock = threading.Lock()
FLAG_RE = re.compile(r"^VULN\{[0-9A-F]{32}\}$")


def log_flag(pid, lab, flag):
    os.makedirs(os.path.dirname(FLAG_LOG) or ".", exist_ok=True)
    with _log_lock, open(FLAG_LOG, "a") as fh:
        fh.write(json.dumps({"pid": pid, "lab": lab, "flag": flag}) + "\n")


class Participant(HttpUser):
    abstract = True
    host = FD_URL
    wait_time = between(1, 3)

    def on_start(self):
        self.vm = HttpSession(base_url=VM_URL, request_event=self.environment.events.request, user=self)
        self.name_ = "lt" + uuid.uuid4().hex[:12]
        self.pid = None
        self.access = None
        self.refresh = None
        self.flags = {}
        self.solved = set()
        self.ready = False
        self.setup()

    def setup(self):
        with self.client.post("/api/register", json={"username": self.name_, "password": PASSWORD}, headers=FD_HEADERS, name="setup: FD register", catch_response=True) as r:
            if r.status_code != 200:
                r.failure(f"register {r.status_code}")
                return
            self.pid = r.json()["id"]
        with self.vm.get("/api/sso/login", allow_redirects=False, name="setup: VM sso/login", catch_response=True) as r:
            if r.status_code != 302:
                r.failure(f"sso login {r.status_code}")
                return
            loc = r.headers["location"]
        path = loc[len(FD_URL):] if loc.startswith(FD_URL) else loc
        with self.client.get(path, allow_redirects=False, name="setup: FD sso/authorize", catch_response=True) as r:
            if r.status_code != 302:
                r.failure(f"authorize {r.status_code}")
                return
            cb = r.headers["location"]
        cbpath = cb[len(VM_URL):] if cb.startswith(VM_URL) else cb
        with self.vm.get(cbpath, allow_redirects=False, name="setup: VM sso/callback", catch_response=True) as r:
            if r.status_code != 302:
                r.failure(f"callback {r.status_code}")
                return
        with self.vm.post("/api/sso/session", headers={"x-vm": "1"}, name="setup: VM sso/session", catch_response=True) as r:
            if r.status_code != 200:
                r.failure(f"session {r.status_code}")
                return
            data = r.json()
            self.access, self.refresh = data["access_token"], data["refresh_token"]
        self.ready = True

    def vm_auth(self):
        return {"Authorization": f"Bearer {self.access}"}

    def browse_shop(self):
        if not self.ready:
            return
        pick = random.random()
        if pick < 0.25:
            self.vm.get("/api/products/home", name="VM home")
        elif pick < 0.5:
            self.vm.get("/api/products", params={"page": random.randint(1, 3)}, name="VM product list")
        elif pick < 0.7:
            self.vm.get("/api/products/search", params={"q": random.choice(["phone", "shirt", "lamp", "book", "chair"])}, name="VM search")
        elif pick < 0.9:
            self.vm.get(f"/api/products/{random.randint(1, 37)}", name="VM product detail")
        else:
            self.vm.get("/api/orders", headers=self.vm_auth(), name="VM my orders")

    def leaderboard(self):
        if self.ready:
            with self.client.get("/api/scoreboard", name="FD scoreboard", catch_response=True) as r:
                if r.status_code != 200:
                    r.failure(f"scoreboard status {r.status_code}")
                elif "rows" not in r.json():
                    r.failure("scoreboard body missing rows")

    def challenges(self):
        if self.ready:
            self.client.get("/api/challenges", name="FD challenges")
            self.client.get("/api/me", name="FD me")

    def trigger_lab(self, lab):
        if lab == "LAB-01":
            with self.vm.post("/api/auth/login", json={"username": "vault.audit", "password": "wrong"}, name="VM lab01 trigger", catch_response=True) as resp:
                try:
                    flag = resp.json()["detail"]["audit_reference"] if resp.status_code == 401 else None
                    if flag:
                        resp.success()
                    else:
                        resp.failure("lab01 no reference")
                    return flag
                except Exception:
                    resp.failure("lab01 parse")
        if lab == "LAB-02":
            with self.vm.post("/api/auth/forgot-password", json={"identifier": "ops.recovery"}, name="VM lab02 trigger", catch_response=True) as resp:
                try:
                    return resp.json()["recovery_ticket"]
                except Exception:
                    resp.failure("lab02 parse")
        if lab == "LAB-04":
            self.vm.post("/api/auth/logout", headers=self.vm_auth(), name="VM lab04 logout")
            with self.vm.post("/api/auth/refresh", json={"refresh_token": self.refresh}, name="VM lab04 refresh", catch_response=True) as resp:
                try:
                    return resp.json()["session_audit"]["reference"]
                except Exception:
                    resp.failure("lab04 parse")
        if lab == "LAB-12":
            return None
        return None

    def solve_one(self, lab=None, duplicate=False):
        if not self.ready:
            return
        todo = [x for x in ("LAB-01", "LAB-02", "LAB-04") if x not in self.solved]
        if lab is None:
            if not todo:
                return
            lab = random.choice(todo)
        flag = self.flags.get(lab) or self.trigger_lab(lab)
        if not flag:
            return
        if not FLAG_RE.match(flag):
            self.environment.events.request.fire(request_type="CHECK", name="flag format", response_time=0, response_length=0, exception=Exception(f"bad flag format {flag[:20]}"), context={})
            return
        self.flags[lab] = flag
        log_flag(self.pid, lab, flag)
        with self.client.post(f"/api/challenges/{lab}/submit", json={"flag": flag}, headers=FD_HEADERS, name="FD submit flag", catch_response=True) as r:
            if r.status_code != 200:
                r.failure(f"submit {r.status_code}")
                return
            status = r.json()["status"]
            if status == "correct":
                self.solved.add(lab)
            elif status == "already_solved":
                self.solved.add(lab)
            elif status == "incorrect":
                r.failure("own flag rejected")


class CombinedUser(Participant):
    @task(10)
    def shop(self):
        self.browse_shop()

    @task(4)
    def board(self):
        self.leaderboard()

    @task(3)
    def chals(self):
        self.challenges()

    @task(2)
    def solve(self):
        self.solve_one()

    @task(1)
    def resubmit(self):
        if self.solved:
            self.solve_one(lab=random.choice(list(self.solved)), duplicate=True)


class VulnMartOnlyUser(Participant):
    @task(8)
    def shop(self):
        self.browse_shop()

    @task(1)
    def labs(self):
        if self.ready:
            self.vm.get("/api/labs", headers=self.vm_auth(), name="VM labs")


class FlagDeskOnlyUser(Participant):
    @task(5)
    def board(self):
        self.leaderboard()

    @task(3)
    def chals(self):
        self.challenges()

    @task(2)
    def solve(self):
        self.solve_one()

    @task(1)
    def resubmit(self):
        if self.solved:
            self.solve_one(lab=random.choice(list(self.solved)), duplicate=True)


class SubmissionBurstUser(Participant):
    wait_time = constant(5)
    expected = int(os.environ.get("BURST_USERS", "50"))

    def on_start(self):
        super().on_start()
        self.burst_flag = None
        if self.ready:
            self.burst_flag = self.trigger_lab("LAB-01")
            if self.burst_flag:
                log_flag(self.pid, "LAB-01", self.burst_flag)
        import gevent
        for _ in range(600):
            if self.environment.runner.user_count >= self.expected:
                break
            gevent.sleep(0.1)

    @task
    def burst(self):
        if not self.burst_flag:
            return
        with self.client.post("/api/challenges/LAB-01/submit", json={"flag": self.burst_flag}, headers=FD_HEADERS, name="FD burst submit", catch_response=True) as r:
            if r.status_code != 200:
                r.failure(f"submit {r.status_code}")
            elif r.json()["status"] == "incorrect":
                r.failure("own flag rejected")


class LeaderboardUser(Participant):
    wait_time = constant(0.5)

    @task
    def board(self):
        self.leaderboard()
