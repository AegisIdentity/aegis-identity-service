package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Per-tenant self-service sign-up policy. A tenant's end-users may only self-register when that
 * tenant has explicitly opted in ({@code enabled = true}). The absence of a row means disabled — so
 * public sign-up is closed by default and can never silently create users in a tenant that did not
 * ask for it.
 */
@Entity
@Table(name = "tenant_signup_policy")
public class TenantSignupPolicy {

    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected TenantSignupPolicy() {
    }

    public TenantSignupPolicy(String tenantId, boolean enabled) {
        this.tenantId = tenantId;
        this.enabled = enabled;
    }

    public String getTenantId() {
        return tenantId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
