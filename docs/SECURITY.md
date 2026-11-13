# Security notes

What is protected, and how it was verified (all tests are in the repository).

| Property | Control | Test |
|---|---|---|
| Single identity | UUID in `identity.participants`, shop user linked by `identity_uuid` | `tests/e2e/test_stack.py::test_username_identical_in_both_apps_and_single_uuid` |
| No shop passwords for participants | `!sso-only` hash, registration closed | `test_local_shop_registration_closed_and_no_password_login` |
| Username collisions | case-insensitive unique + reserved list (shop personas, organizers, admin names) | `FlagDesk tests/test_core.py::test_username_collisions_and_reserved` |
| No role self-assignment | role is never read from the request | `test_role_cannot_be_self_assigned` |
| Exactly two organizers, hidden | env provisioning, TOTP, DB trigger, filtered queries | `test_organizers_hidden_and_two_only`, e2e `test_organizer_isolation_and_dashboard` |
| No account enumeration at login | identical response, dummy hash for unknown names | `test_register_login_and_enumeration` |
| Flags are participant-bound | HMAC over participant UUID + challenge + event + version | `test_flag_lifecycle_and_scoring`, `test_wrong_challenge_and_foreign_flag`, load-test ownership check |
| `VULN{}` only | single format, regex validation, legacy format rejected | `test_no_legacy_prefix_anywhere`, `test_legacy_format_rejected` |
| Un-issued flags are worthless | submission requires an issued row | `test_unissued_flag_never_accepted` |
| Secret not in shop/DB | env of FlagDesk only; DB scan | e2e `test_shop_never_stores_flags_or_secrets_in_db` |
| Rotate / revoke | `flag_state.version`, `revoked` | `test_rotate_and_revoke` |
| No double scoring under races | unique constraint + atomic upsert | `test_concurrent_duplicate_submission_scores_once` |
| SSO one-time codes | consumed with GETDEL, bound to redirect URI and client | `test_sso_flow_and_revocation`, `test_sso_rejects_unregistered_redirect` |
| Session revocation | server-side session rows, introspection | `test_sso_flow_and_revocation`, e2e `test_logout_at_flagdesk_stops_flag_issuance` |
| Lab flaws cannot forge outer identity | separate HS256 secret, different audience | `test_forged_outer_cookie_rejected`, `test_inner_jwt_confusion_cannot_forge_outer_identity` |
| DB isolation | role grants | `test_vulnmart_role_cannot_read_identity_or_flagdesk` |
| Service API auth | bearer token compared as SHA-256 in constant time; `/internal/` not routed by nginx | `test_service_auth_required` |
| CSRF | `X-FD` / `X-VM` header on state-changing calls, SameSite=Lax | `test_csrf_header_required` |
| Brute force | wrong-flag limit per participant, login limits per name and IP | e2e `test_wrong_attempt_rate_limit` |

## Intentional weaknesses that remain (by design)

The twelve VulnMart labs are unchanged: username enumeration, IDOR, broken session handling, privilege escalation, XSS (reflected, stored, DOM), SQL injection, JWT key confusion and partial-MFA bypass.
All 36 original VulnMart tests still pass; the secure mode behaviour is unchanged.

## Known limitations (read these)

1. **LAB-09 (DOM XSS)** cannot be detected server-side, so its flag cookie is issued when the promo page is opened by a signed-in participant, as in the original lab. A participant can read it without exploiting the DOM flaw.
2. **Shared persona accounts.** The seeded shop personas (gautham.shop etc.) are shared by everyone who chooses to log into them. Labs 03 and 06 target other users' data, so this is fine; changing a persona's password can disturb others. Participants' own SSO shop accounts are private.
3. **Sentinel visibility.** A participant who exploits SQL injection (LAB-10) can read the other sentinel markers. A marker alone yields nothing: flags are produced by FlagDesk only after the server-side objective check, and user input containing the marker is rejected.
4. **Organizer MFA** is TOTP; there is no recovery flow. Keep the secrets safe.
5. **No TLS inside the Docker network.** Use the `https` profile (Caddy) or your own terminator at the edge.
6. **CSRF protection** relies on a custom header plus SameSite=Lax.
7. **Participants can see usernames** of other participants (scoreboard), as in any CTF.
