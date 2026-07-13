# aegis-identity-service — working notes

**Maturity: core.** Users/credentials/groups. Package `io.aegis.identity`. Port 9102. Postgres.
OAuth2 resource server (validates JWTs against the AS issuer).

## Where things are
- `service/PasswordHasher` — Argon2id (needs Bouncy Castle). The single place hashing is defined.
- `service/UserService` — create + `authenticate` with lockout (5 failures ⇒ locked 15m). Never
  reveals whether a username exists (always BAD_CREDENTIALS) — anti-enumeration.
- `domain/AppUserRepository` — all finders are **tenant-scoped by construction** (no bare findById).
- `config/SecurityConfig` — default-deny; each endpoint requires a specific scope.

## Non-negotiables
- No cross-tenant reads — every query carries a tenant; there is a negative test proving isolation.
- Passwords: Argon2id only; wrong password never distinguishable from unknown user to the caller.
- New endpoints ship with a positive and a **negative** authz test (401 no token, 403 wrong scope).

## Build / test
`mvn verify` (Docker required). Coverage floor 0.60.
