# Operations, capacity and deployment

## Recommended sizing for 150 concurrent participants

Starting point (to be confirmed by running the load matrix on the real host):

| Resource | Recommendation |
|---|---|
| VM (apps, nginx, Redis, PgBouncer) | 4 vCPU, 16 GB RAM (e.g. GCP e2-standard-4 on the free-trial credit). 2 vCPU / 8 GB is the floor and was CPU-bound in testing |
| PostgreSQL (your existing server) | 2 vCPU / 4 GB is enough for this workload; the database was never the bottleneck in testing (about 34% of one core at peak) |
| FlagDesk | `WEB_CONCURRENCY=2` (3 on 4+ vCPU), container limit 1.5 CPU / 768 MB |
| VulnMart backend | `WEB_CONCURRENCY=2` (3 on 4+ vCPU), container limit 2 CPU / 1 GB |
| Redis | 128 MB, `volatile-lru`, no persistence; used for one-time SSO codes (60 s) and rate counters only |
| nginx | per-IP limit 300 r/s, burst 600, 400 connections, deliberately high because a whole room may share one NAT address |

Connection budget (PostgreSQL `max_connections` must exceed all of it plus your other users of that server):

| Layer | Setting | Value |
|---|---|---|
| App pool, FlagDesk | `POOL_SIZE` + `POOL_OVERFLOW`, per worker | 10 + 10 |
| App pool, VulnMart | `DB_POOL_SIZE` + `DB_MAX_OVERFLOW`, per worker | 12 + 12 |
| Thread pools | `THREADPOOL_SIZE` (FlagDesk 18) / `threadpool_size` (VulnMart 22) | just under the pool size so threads never starve for a connection |
| PgBouncer | transaction mode, `PGB_POOL_SIZE` per user/db | 20, `max_db_connections` 60 |
| Role limits | `flagdesk_app` 80, `vulnmart_app` 50 | set by `scripts/db_bootstrap.py` |
| Timeouts | statement 10 s (FlagDesk) / 8 s (VulnMart), idle-in-transaction 15 s, pool wait 10 s | |

Rule of thumb: PgBouncer `max_db_connections` + 10 headroom <= `max_connections` of the shared server. If the server is small or shared, lower `PGB_MAX_DB_CONNECTIONS` to 30; requests queue briefly in PgBouncer instead of failing.

Scaling: raise workers first (CPU bound), then add a second VM running the same compose services behind a load balancer. Both apps are stateless (sessions and scores are in PostgreSQL, codes in Redis; point both VMs at one Redis). The shop mode cache and JWKS cache are per process and refresh within seconds.

## What the load tests found

1. The first 150-user run exposed a real defect: VulnMart's per-request mode lookup took an extra pooled connection and its pool (5+5) was smaller than its 40 request threads. Result: pool timeouts, p95 11-18 s, 2.8 % errors. Fixed by a single-flight 2 s mode cache, pools of 12+12 and a thread pool limit below the pool size. The failing log is kept in `reports/_findings/`.
2. VulnMart signing keys were created without a lock, so two workers could generate different RSA keys. Fixed with a file lock and atomic replace.
3. Uvicorn's default 5 s keep-alive caused a handful of dropped reused connections at a 5 s client cadence; the container command sets `--timeout-keep-alive 15` and the test stack 30.

See `reports/LOADTEST_RESULTS.md` for the final tables and pass/fail per objective. Those numbers come from a 2-vCPU sandbox that also hosted the load generator, so use them only to compare, not to size.

## Deployment (Google Cloud trial credit, your own PostgreSQL)

1. Create a VM (Ubuntu 22.04/24.04, e2-standard-4), open ports 80/443 (or 8081 for HTTP tests), install Docker + the compose plugin.
2. Point two DNS names at the VM, e.g. `ctf.<ip>.sslip.io` and `shop.<ip>.sslip.io` (free), or your own domain. They must be different hostnames: cookies are host-only, which isolates the two apps.
3. Allow the VM's IP in your PostgreSQL server's firewall. You need an admin login that can create roles and a database (`CREATEROLE`, `CREATEDB`); managed services that forbid `CREATEROLE` need the roles created by their admin console using the same names (`ctf_migrator`, `flagdesk_app`, `vulnmart_app`).
4. `git clone` the repository, `cd deploy`, `cp .env.example .env`. Fill it in. Generate secrets with `python3 ../scripts/gen_secrets.py` (prints values to stdout; organizer authenticator URIs go to stderr: scan them with an authenticator app, then keep them off any shared screen).
5. For HTTPS: `PUBLIC_SCHEME=https`, `PUBLIC_PORT=443`, `COOKIE_SECURE=1`, `ENVIRONMENT=training`, `NGINX_BIND=127.0.0.1`, and start with `--profile https`.
6. `./prepare.sh` (writes the PgBouncer config and the service token hash), then `docker compose --env-file .env up -d --build` (add `--profile https` if used).
7. Open `https://<CTF_HOST>`; organizers sign in at `https://<CTF_HOST>/#organizer`.

First start order is enforced by compose: `init-flagdesk` (roles, schemas, grants, FlagDesk migrations) -> `init-shop` (shop migrations and seed) -> apps -> nginx.

### Starting from a clean database

`scripts/db_wipe.py` prints the server, database name and every schema with table counts, then requires you to type the database name. Without `--everything` it only drops the four platform schemas and refuses if other objects exist.

```
export ADMIN_DATABASE_URL=... DB_NAME=...
python3 scripts/db_wipe.py --confirm-db-name "$DB_NAME"
python3 scripts/db_wipe.py --confirm-db-name "$DB_NAME" --everything   # clears everything else in that database
```

## Day-to-day

- Rotate or revoke a participant's flag: organizer dashboard -> Flag control.
- Disable a participant: dashboard -> Participants (their sessions end at once).
- Reset an event: wipe, then `docker compose up -d` again (or delete participant rows only).
- Rotating `FLAG_SECRET` invalidates every flag; do it only between events.
- Lab mode is fixed by `ENVIRONMENT=training` (training mode needs `training`/`local`/`development`).

## Re-running the load tests on the real host

```
pip install locust psutil
export FLAGDESK_DB_PASSWORD=... VULNMART_DB_PASSWORD=... ADMIN_DSN=postgresql://.../<DB_NAME>
python3 loadtest/run_matrix.py users150_combined vulnmart150 flagdesk150 submit50 leaderboard100 sustained30m
python3 loadtest/report.py
```

`scripts/dev_stack.py` starts the apps with the dev secrets used by the harness; on a real host point `FD_URL`/`VM_URL` at the deployed stack and run Locust directly (`locust -f loadtest/locustfile.py CombinedUser -u 150 -r 15 -t 30m --headless`), then `loadtest/verify.py` for the SQL correctness checks using the real `FLAG_SECRET` in `VERIFY_FLAG_SECRET`. Raise the registration and login rate limits for the test (`REGISTER_IP_LIMIT`, `IP_LOGIN_LIMIT`) because every simulated user shares one IP.
