--
-- Baseline schema for identity-service.
--
-- GENERATED from the JPA entities by Hibernate's schema exporter, not hand-written. The service
-- runs with ddl-auto: validate, so any drift between this file and the entities fails startup —
-- generating it is what guarantees the two agree.
--
-- Regenerate after an entity change (then add a NEW V<n>__ migration; never edit an applied one):
--   mvn -o verify -Dit.test=<AnIT> -DfailIfNoSpecifiedTests=false \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.action=create \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.create-target=target/generated-schema.sql
--
-- Existing (pre-Flyway) databases are handled by flyway.baseline-on-migrate=true: they are marked
-- at the baseline version and this migration is skipped, since their tables already exist.
--
create table app_user (failed_login_attempts integer not null, created_at timestamp(6) with time zone not null, locked_until timestamp(6) with time zone, updated_at timestamp(6) with time zone not null, id uuid not null, status varchar(16) not null check ((status in ('ACTIVE','DISABLED','LOCKED'))), tenant_id varchar(64) not null, username varchar(128) not null, email varchar(320) not null, password_hash varchar(512) not null, primary key (id), constraint uq_app_user_tenant_username unique (tenant_id, username), constraint uq_app_user_tenant_email unique (tenant_id, email));

create table audit_event (created_at timestamp(6) with time zone not null, id uuid not null, action varchar(64) not null, tenant_id varchar(64) not null, actor varchar(320) not null, target varchar(320), detail varchar(512), primary key (id));

create table auth_policy (lockout_duration_minutes integer not null, lockout_threshold integer not null, mfa_required boolean not null, password_min_length integer not null, password_require_digit boolean not null, password_require_lowercase boolean not null, password_require_symbol boolean not null, password_require_uppercase boolean not null, session_ttl_minutes integer not null, updated_at timestamp(6) with time zone not null, mfa_methods varchar(64), tenant_id varchar(64) not null, primary key (tenant_id));

create table group_membership (group_id uuid not null, id uuid not null, user_id uuid not null, tenant_id varchar(64) not null, primary key (id), constraint uq_group_membership unique (group_id, user_id));

create table tenant_branding (primary_color varchar(7) not null, updated_at timestamp(6) with time zone not null, product_name varchar(64) not null, tenant_id varchar(64) not null, sign_in_heading varchar(160) not null, sign_in_subtitle varchar(280) not null, primary key (tenant_id));

create table tenant_signup_policy (enabled boolean not null, updated_at timestamp(6) with time zone not null, tenant_id varchar(64) not null, primary key (tenant_id));

create table user_group (created_at timestamp(6) with time zone not null, id uuid not null, tenant_id varchar(64) not null, name varchar(128) not null, description varchar(512), primary key (id), constraint uq_user_group_tenant_name unique (tenant_id, name));

create index idx_audit_event_tenant_created on audit_event (tenant_id, created_at);

