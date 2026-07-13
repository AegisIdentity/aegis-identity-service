package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * An audit record of a security-relevant operation, tenant-scoped throughout. Backs the console's
 * "System Log" page. Best-effort: an audit write failure must never break the primary operation.
 *
 * <p>Audit events must never carry secrets (passwords, tokens, full assertions) — see
 * aegis-platform-commons non-negotiables. {@code detail} is intentionally short and non-sensitive.
 */
@Entity
@Table(name = "audit_event", indexes = {
        @Index(name = "idx_audit_event_tenant_created", columnList = "tenant_id, created_at")
})
public class AuditEvent {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    /** Who acted — an end-user's username/subject, or "system" for platform-initiated events. */
    @Column(nullable = false, updatable = false, length = 320)
    private String actor;

    /** What happened, e.g. {@code USER_CREATED}, {@code AUTH_FAILURE}, {@code PASSWORD_CHANGED}. */
    @Column(nullable = false, updatable = false, length = 64)
    private String action;

    /** The affected username/resource, when applicable. */
    @Column(updatable = false, length = 320)
    private String target;

    /** A short, non-sensitive note. Never a secret. */
    @Column(updatable = false, length = 512)
    private String detail;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected AuditEvent() {
    }

    public AuditEvent(UUID id, String tenantId, String actor, String action, String target, String detail) {
        this.id = id;
        this.tenantId = tenantId;
        this.actor = actor;
        this.action = action;
        this.target = target;
        this.detail = detail;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getActor() {
        return actor;
    }

    public String getAction() {
        return action;
    }

    public String getTarget() {
        return target;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
