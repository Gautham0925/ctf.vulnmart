# Architecture

One platform, two applications, one PostgreSQL database.

| Piece | Role |
|---|---|
| **FlagDesk** (`flagdesk/`) | Identity provider and SSO, flag derivation and validation, scoring, challenge registry, organizer dashboard |
| **VulnMart** (`vulnmart/`) | The intentionally vulnerable shop with 12 labs (LAB-01 to LAB-12). It owns no participant identity and no flag secret |
| **PostgreSQL** | One database, four schemas, least-privilege roles |
| **PgBouncer** | Transaction pooling in front of both apps |
| **Redis** | One-time SSO codes, rate counters |
| **nginx** | Edge: two virtual hosts (`CTF_HOST` for FlagDesk, `SHOP_HOST` for VulnMart), generous per-IP limits, `/internal/` blocked |

## Identity

Every participant has one UUID in `identity.participants`. The username is identical in both apps because VulnMart creates its
local shop user from the SSO assertion (`username = preferred_username`, `identity_uuid = sub`). FlagDesk reserves the
VulnMart persona names (alice.morgan, admin, ...) and both organizer names, so a participant can never collide with a seeded shop user.
Usernames are unique case-insensitively (`username_norm`, NFKC + lower-case).

VulnMart participants have no shop password (`password_hash = '!sso-only'`, synthetic `uuid@sso.invalid` email) and shop registration is closed.

### Roles

- `participant`: everyone who registers.
- `organizer`: exactly two accounts, created only from environment variables at FlagDesk start-up (`ORGANIZER_1_*`, `ORGANIZER_2_*`).
  Password + TOTP. A database trigger refuses a third organizer. Organizers are excluded from the scoreboard, participant lists, counts and
  SSO. Registration and the participant login endpoint treat their usernames exactly like any taken username (no enumeration).
  Role is derived server-side from the database row on every request; nothing in the browser can change it.

## SSO

```
Browser -> shop /api/sso/login            (state cookie set, 302)
Browser -> FlagDesk /sso/authorize        (participant session cookie; one-time code, 60 s, bound to client + redirect_uri)
Browser -> shop /api/sso/callback?code    (state checked)
shop    -> FlagDesk /internal/sso/exchange (service token; code consumed atomically)
shop    <- signed assertion (ES256; iss, aud, exp, iat, sub, sid, jti)
shop    verifies via FlagDesk JWKS, provisions or links the local user, sets HttpOnly cookie vm_sso (separate secret)
SPA     -> POST /api/sso/session          (cookie + X-VM header) -> inner VulnMart lab tokens
```

- Cookies are HttpOnly, SameSite=Lax, Secure in production, host-only. No token is stored in `localStorage`.
- The shop's *inner* JWT is the deliberately vulnerable lab surface (key confusion, no revocation in training mode). It is separate from
  the outer `vm_sso` cookie, which uses a different secret and cannot be forged through the lab flaws (tested).
- Revocation: logout, disabling a participant or session expiry at FlagDesk makes `/internal/identity/introspect` report inactive; the shop checks it at most every 10 s per session before issuing any flag.

## Flags

`VULN{` + 32 upper-case hex characters + `}`. `FLAG{}` does not exist anywhere (tests assert this).

```
flag = "VULN{" + upper(hex(HMAC-SHA256(HKDF(FLAG_SECRET,"flagdesk-flag-v1"),
       "v1\0" + event_id + "\0" + participant_uuid + "\0" + challenge_id + "\0" + version))[:32]) + "}"
```

- 128 bits of MAC output, participant-specific, stable for a given version, unique per participant and challenge.
- `FLAG_SECRET` lives only in FlagDesk's environment. VulnMart, the browser and the database never see it. No flag is stored in the shop database (a test scans every text column).
- Flags are issued only when VulnMart reports a lab objective (`POST /internal/objectives`), recorded in `flagdesk.issued_flags` with a UNIQUE digest.
- Submissions are accepted only if the flag matches the *current* version, has been issued, and is compared in constant time.
- Organizers can rotate (version + 1, old flag dies) or revoke (no flag until rotated) per participant and challenge.
- Foreign-flag submissions are detected through the digest table and written to the audit log.

### Labs that used a shared static flag

| Lab | Mechanism now |
|---|---|
| 01, 02, 04, 05, 11, 12 | The vulnerable response field carries the requesting participant's flag, obtained from FlagDesk |
| 03, 06 | The seeded data holds a keyed *sentinel*; the response substitutes the viewer's flag when the objective is reached |
| 07, 09 | Cookie value is the viewer's flag (09 issues on page visit; see Known limitations) |
| 08 | Cookie only when the markup review was written by the viewer's own account |
| 10 | The secret row holds a sentinel; the search response substitutes the viewer's flag |

Sentinels are HMAC-keyed and user-written fields containing the marker are rejected, so they cannot be planted.

## Scoring

`INSERT ... ON CONFLICT DO NOTHING RETURNING` into `flagdesk.solves` (UNIQUE `participant_id, challenge_id`), then an atomic
`INSERT ... ON CONFLICT DO UPDATE` on `flagdesk.scores`, all in one transaction. Duplicate or racing submissions award points once (20-way race test).

## Database

| Schema | Used by | Contents |
|---|---|---|
| `identity` | FlagDesk | participants, sessions, reserved usernames |
| `flagdesk` | FlagDesk | events, challenges, lab mappings, flag state, issued flags, solves, scores, submissions |
| `vulnmart` | VulnMart | the 24 shop tables |
| `audit` | FlagDesk | audit events, objective events |

Roles: `ctf_migrator` (owns objects, runs Alembic), `flagdesk_app` (identity, flagdesk, audit), `vulnmart_app` (vulnmart only).
`vulnmart_app` cannot read or write the other schemas, cannot create objects, has `search_path = vulnmart` (set on the role, so it survives PgBouncer
transaction pooling and keeps the lab-10 raw SQL working with unqualified table names), a connection limit and statement/idle-transaction timeouts. A test proves `permission denied` on identity/flagdesk/audit.

Migrations: `flagdesk/migrations` (identity, flagdesk, audit) and `vulnmart/backend/migrations` (vulnmart), each with its own version table.

## Challenge mapping

`flagdesk.lab_mappings` maps `LAB-nn` to a challenge; `/internal/challenges` exposes it. Disabling a challenge or mapping stops issuance.

## Locked down in integrated mode

Because participants can legitimately reach the shop's admin APIs through LAB-05/LAB-11, global mode switching and lab reset are disabled
(`CTF_ENABLED=1`); organizers control the mode with the `ENVIRONMENT`/`APP_MODE` settings.
