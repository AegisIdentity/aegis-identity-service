# aegis-identity-service — working notes

**Maturity: core.** Users/credentials/groups. Package `io.aegis.identity`. Port 9102. Postgres.
OAuth2 resource server (validates JWTs against the AS issuer).

## Where things are
- `service/PasswordHasher` — Argon2id (needs Bouncy Castle). The single place hashing is defined.
- `service/UserService` — create + `authenticate` with lockout (5 failures ⇒ locked 15m). Never
  reveals whether a username exists (always BAD_CREDENTIALS) — anti-enumeration.
- `service/SignupService` + `domain/TenantSignupPolicy` — self-service end-user sign-up, **opt-in per
  tenant, default OFF**. Public `POST /api/v1/signup` succeeds only if the tenant opted in; a closed or
  unknown org returns the same 403 (no enumeration). Admin `GET/PUT /api/v1/signup-policy` toggles it,
  tenant taken from the token.
- `config/ResourceServerJwtConfig` — JWT decoder that fetches JWKS from an in-network URI and validates
  `iss` against an **allowlist** (browser issuer + in-network issuer). Do NOT revert to a single
  `spring...jwt.issuer-uri`: the browser and in-network callers see the AS on different hosts, so one
  issuer-uri rejects one of them (silent 401). See the class javadoc.
- `domain/AppUserRepository` — all finders are **tenant-scoped by construction** (no bare findById).
- `config/SecurityConfig` — default-deny; each endpoint requires a specific scope.

## Non-negotiables
- No cross-tenant reads — every query carries a tenant; there is a negative test proving isolation.
- Passwords: Argon2id only; wrong password never distinguishable from unknown user to the caller.
- New endpoints ship with a positive and a **negative** authz test (401 no token, 403 wrong scope).

## Build / test
`mvn verify` (Docker required). Coverage floor 0.60.
