import os
import string
import sys

root = os.path.join(os.path.dirname(__file__), "..", "deploy", "pgbouncer")
env = {"DB_NAME": os.environ["DB_NAME"], "DB_HOST": os.environ["DB_HOST"], "DB_PORT": os.environ.get("DB_PORT", "5432"), "PGB_POOL_SIZE": os.environ.get("PGB_POOL_SIZE", "20"), "PGB_MAX_DB_CONNECTIONS": os.environ.get("PGB_MAX_DB_CONNECTIONS", "60"), "PGB_SERVER_SSLMODE": os.environ.get("PGB_SERVER_SSLMODE", "prefer")}
tmpl = open(os.path.join(root, "pgbouncer.ini.tmpl")).read()
open(os.path.join(root, "pgbouncer.ini"), "w").write(string.Template(tmpl).substitute(env))
users = [("flagdesk_app", os.environ["FLAGDESK_DB_PASSWORD"]), ("vulnmart_app", os.environ["VULNMART_DB_PASSWORD"])]
with open(os.path.join(root, "userlist.txt"), "w") as fh:
    for u, p in users:
        fh.write('"%s" "%s"\n' % (u, p.replace('"', '""')))
os.chmod(os.path.join(root, "userlist.txt"), 0o600)
print("rendered pgbouncer.ini and userlist.txt for", env["DB_NAME"], "->", env["DB_HOST"])
