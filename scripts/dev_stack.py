import hashlib
import os
import signal
import subprocess
import sys
import time

import httpx

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SVC_TOKEN = "dev-service-token-0123456789abcdef"
FD_PORT, VM_PORT = 8100, 8101
FD_URL, VM_URL = f"http://127.0.0.1:{FD_PORT}", f"http://localhost:{VM_PORT}"
DB_HOST = os.environ.get("DB_HOST", "localhost:5432")
DB_NAME = os.environ.get("DB_NAME", "ctf_dev")


def env_flagdesk():
    return {
        **os.environ,
        "DATABASE_URL": f"postgresql://flagdesk_app:{os.environ['FLAGDESK_DB_PASSWORD']}@{DB_HOST}/{DB_NAME}",
        "REDIS_URL": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        "FLAG_SECRET": "flag-secret-" + "a" * 40,
        "SESSION_SECRET": "session-secret-" + "b" * 40,
        "TOTP_ENC_KEY": "totp-key-" + "c" * 40,
        "SSO_PRIVATE_KEY_FILE": "/tmp/dev_stack_sso.pem",
        "SSO_ISSUER": FD_URL,
        "SSO_CLIENTS": '{"vulnmart-shop": {"redirect_uris": ["%s/api/sso/callback"], "audience": "vulnmart-shop"}}' % VM_URL,
        "VULNMART_SERVICE_TOKEN_SHA256": hashlib.sha256(SVC_TOKEN.encode()).hexdigest(),
        "SHOP_PUBLIC_URL": VM_URL,
        "ENVIRONMENT": "development",
        "ORGANIZER_1_USERNAME": "org.alpha", "ORGANIZER_1_PASSWORD": "Alpha-Pass-12345", "ORGANIZER_1_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
        "ORGANIZER_2_USERNAME": "org.beta", "ORGANIZER_2_PASSWORD": "Beta-Pass-12345", "ORGANIZER_2_TOTP_SECRET": "KRSXG5CTMVRXEZLU",
        "WRONG_LIMIT": "8",
        "REGISTER_IP_LIMIT": "100000", "IP_LOGIN_LIMIT": "100000", "LOGIN_LIMIT": "1000",
    }


def env_vulnmart():
    return {
        **os.environ,
        "DATABASE_URL": f"postgresql+psycopg://vulnmart_app:{os.environ['VULNMART_DB_PASSWORD']}@{DB_HOST}/{DB_NAME}",
        "REDIS_URL": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        "CTF_ENABLED": "1",
        "FLAGDESK_INTERNAL_URL": FD_URL,
        "FLAGDESK_PUBLIC_URL": FD_URL,
        "FLAGDESK_SERVICE_TOKEN": SVC_TOKEN,
        "SSO_ISSUER": FD_URL,
        "SHOP_PUBLIC_URL": VM_URL,
        "SHOP_SESSION_SECRET": "shop-session-" + "d" * 40,
        "LOCAL_REGISTRATION_ENABLED": "0",
        "ENVIRONMENT": "training",
        "KEYS_DIR": "/tmp/dev_stack_keys",
    }


def start(workers_fd=2, workers_vm=2):
    procs = []
    procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(FD_PORT), "--workers", str(workers_fd), "--log-level", "warning"], cwd=os.path.join(ROOT, "flagdesk"), env=env_flagdesk()))
    procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(VM_PORT), "--workers", str(workers_vm), "--log-level", "warning"], cwd=os.path.join(ROOT, "vulnmart", "backend"), env=env_vulnmart()))
    for url in (FD_URL + "/api/health", VM_URL + "/api/health"):
        for _ in range(120):
            try:
                if httpx.get(url, timeout=2).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            stop(procs)
            raise RuntimeError("did not start: " + url)
    return procs


def stop(procs):
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except Exception:
            p.kill()


if __name__ == "__main__":
    ps = start()
    print("running", FD_URL, VM_URL)
    try:
        while True:
            time.sleep(3600)
    finally:
        stop(ps)
