--
-- AI agent principals (ADR-0010 / AGENT-IDENTITY-ARCHITECTURE.md).
--
-- An agent is a non-human, DELEGATED principal. The column that carries the design is
-- owner_principal: it is NOT NULL, because an agent nobody owns is an agent nobody will notice
-- misbehaving. "The agent did it" has to resolve to a party who can be notified, escalated to, and
-- asked whether the agent should still exist.
--
-- Tenant-scoped exactly like app_user: agent_id is unique PER TENANT, never globally.
--
CREATE TABLE IF NOT EXISTS agent_identity (
    id                   uuid         NOT NULL,
    tenant_id            varchar(64)  NOT NULL,
    agent_id             varchar(128) NOT NULL,
    display_name         varchar(200) NOT NULL,
    owner_principal      varchar(200) NOT NULL,
    status               varchar(16)  NOT NULL DEFAULT 'ACTIVE',
    autonomy             varchar(16)  NOT NULL DEFAULT 'CONFIRM_EACH',
    max_delegation_depth integer      NOT NULL DEFAULT 3,
    created_at           timestamptz  NOT NULL,
    updated_at           timestamptz  NOT NULL,
    revoked_at           timestamptz,
    revoked_reason       varchar(500),
    PRIMARY KEY (id),
    CONSTRAINT uq_agent_identity_tenant_agent UNIQUE (tenant_id, agent_id),
    CONSTRAINT ck_agent_identity_status    CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    CONSTRAINT ck_agent_identity_autonomy  CHECK (autonomy IN ('CONFIRM_EACH','SUPERVISED','AUTONOMOUS')),
    -- A negative or unbounded delegation depth would defeat the chain-depth ceiling entirely.
    CONSTRAINT ck_agent_identity_depth     CHECK (max_delegation_depth BETWEEN 0 AND 10)
);

-- "What am I accountable for?" is a question owners will ask constantly, and it is the query an
-- offboarding process runs, so it gets an index rather than a sequential scan.
CREATE INDEX IF NOT EXISTS ix_agent_identity_owner
    ON agent_identity (tenant_id, owner_principal);

CREATE INDEX IF NOT EXISTS ix_agent_identity_tenant_status
    ON agent_identity (tenant_id, status);
