# VULNMART + FlagDesk: unified CTF platform

FlagDesk is the identity provider, SSO, flag authority and scoreboard. VulnMart is the intentionally vulnerable shop (12 labs). One PostgreSQL database, four schemas, one participant UUID, `VULN{...}` per-participant flags.

- `flagdesk/` identity, SSO, flags, scoring, organizer dashboard
- `vulnmart/` shop backend (FastAPI) and frontend (React)
- `deploy/` Docker Compose, nginx, PgBouncer, Caddy (HTTPS)
- `scripts/` database bootstrap, guarded wipe, secret generation, dev stack
- `loadtest/` Locust scenarios, resource sampler, correctness verifier, report generator
- `tests/e2e/` end-to-end tests over real processes
- `docs/` ARCHITECTURE, SECURITY, OPERATIONS

Tests: `cd flagdesk && python -m pytest tests`, `cd vulnmart/backend && python -m pytest tests`, `python -m pytest tests/e2e` (the last two need the bootstrapped database roles; see docs/OPERATIONS.md).

Training use only. VulnMart contains deliberate vulnerabilities; do not expose it outside an event network you control.
