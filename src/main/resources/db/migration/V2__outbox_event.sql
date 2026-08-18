--
-- Transactional outbox for identity business events (identity.user.*).
--
-- Rows are written in the SAME transaction as the user mutation (OutboxWriter), so an event cannot be
-- lost between the DB commit and the Kafka publish. OutboxRelay polls unpublished rows, publishes to
-- the row's topic, and marks them published (at-least-once; consumers are idempotent).
--
CREATE TABLE IF NOT EXISTS outbox_event (
    id             uuid         NOT NULL,
    aggregate_type varchar(32)  NOT NULL,
    aggregate_id   varchar(64)  NOT NULL,
    event_type     varchar(64)  NOT NULL,
    topic          varchar(128) NOT NULL,
    message_key    varchar(64)  NOT NULL,
    payload        text         NOT NULL,
    created_at     timestamptz  NOT NULL,
    published      boolean      NOT NULL DEFAULT FALSE,
    published_at   timestamptz,
    PRIMARY KEY (id)
);

-- The relay's hot query: unpublished rows oldest-first.
CREATE INDEX IF NOT EXISTS ix_outbox_unpublished ON outbox_event (published, created_at);
