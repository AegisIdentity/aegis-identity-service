# aegis-identity-service

The **universal directory** — users, credentials (**Argon2id**), groups. Tenant-scoped. Verifies
passwords for the authorization-server. Crown-jewel data. Port `9102`. Store: PostgreSQL.

## Key endpoints
`POST /api/v1/users` (scope `identity:users:write`), `GET /api/v1/users/{id}`
(`identity:users:read`), `POST /api/v1/users:authenticate` (`identity:users:authenticate`).

## Build
```bash
mvn verify   # 11 tests vs real Postgres: Argon2, tenant isolation, lockout, scope authz
```
