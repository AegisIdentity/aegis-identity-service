package io.aegis.identity.agent;

import io.aegis.commons.agent.AgentPrincipal;
import io.aegis.commons.agent.AgentStatus;
import io.aegis.commons.agent.AutonomyLevel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * A registered AI agent — a non-human, delegated principal.
 *
 * <p>{@code ownerPrincipal} is the <b>owner edge</b> and is non-null by construction. It is what
 * makes "the agent did it" answerable: there is always a party to notify, escalate to and hold
 * accountable. Agents are tenant-scoped exactly like users, and {@code agentId} is unique
 * <em>per tenant</em>, never globally.
 */
@Entity
@Table(name = "agent_identity", uniqueConstraints =
        @UniqueConstraint(name = "uq_agent_identity_tenant_agent", columnNames = {"tenant_id", "agent_id"}))
public class AgentIdentity {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    /** Namespaced agent id, e.g. {@code agent:planner}. */
    @Column(name = "agent_id", nullable = false, updatable = false, length = 128)
    private String agentId;

    @Column(name = "display_name", nullable = false, length = 200)
    private String displayName;

    /** The accountable human or service. Never null — see class javadoc. */
    @Column(name = "owner_principal", nullable = false, length = 200)
    private String ownerPrincipal;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AgentStatus status = AgentStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AutonomyLevel autonomy = AutonomyLevel.CONFIRM_EACH;

    /** Ceiling on how deep this agent may delegate onward. */
    @Column(name = "max_delegation_depth", nullable = false)
    private int maxDelegationDepth = 3;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_reason", length = 500)
    private String revokedReason;

    protected AgentIdentity() {
    }

    public AgentIdentity(String tenantId, String agentId, String displayName, String ownerPrincipal) {
        if (ownerPrincipal == null || ownerPrincipal.isBlank()) {
            throw new IllegalArgumentException("agent ownerPrincipal is required");
        }
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.agentId = agentId;
        this.displayName = displayName;
        this.ownerPrincipal = ownerPrincipal;
    }

    public void revoke(String reason) {
        this.status = AgentStatus.REVOKED;
        this.revokedAt = Instant.now();
        this.revokedReason = reason;
        this.updatedAt = Instant.now();
    }

    /**
     * @throws IllegalStateException if the agent was revoked. Revocation is terminal: reactivating
     *                               would silently restore every consent and mandate the compromised
     *                               identity still held. Register a new agent instead.
     */
    public void activate() {
        if (status == AgentStatus.REVOKED) {
            throw new IllegalStateException(
                    "agent " + agentId + " is revoked; revocation is terminal — register a new agent");
        }
        this.status = AgentStatus.ACTIVE;
        this.updatedAt = Instant.now();
    }

    public void suspend() {
        if (status != AgentStatus.REVOKED) {
            this.status = AgentStatus.SUSPENDED;
            this.updatedAt = Instant.now();
        }
    }

    public void setAutonomy(AutonomyLevel autonomy) {
        this.autonomy = autonomy == null ? AutonomyLevel.CONFIRM_EACH : autonomy;
        this.updatedAt = Instant.now();
    }

    public boolean canAct() {
        return status == AgentStatus.ACTIVE;
    }

    /** Project onto the shared, protocol-agnostic type used across the platform. */
    public AgentPrincipal toAgentPrincipal() {
        return new AgentPrincipal(agentId, tenantId, ownerPrincipal, autonomy, status, createdAt);
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getAgentId() {
        return agentId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getOwnerPrincipal() {
        return ownerPrincipal;
    }

    public AgentStatus getStatus() {
        return status;
    }

    public AutonomyLevel getAutonomy() {
        return autonomy;
    }

    public int getMaxDelegationDepth() {
        return maxDelegationDepth;
    }

    public void setMaxDelegationDepth(int maxDelegationDepth) {
        this.maxDelegationDepth = maxDelegationDepth;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public String getRevokedReason() {
        return revokedReason;
    }
}
