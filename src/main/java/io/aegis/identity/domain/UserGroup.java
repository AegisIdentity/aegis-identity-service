package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/** A group of users. Tenant-scoped; group name is unique per tenant. ("group" is a SQL reserved
 * word, hence the {@code user_group} table.) */
@Entity
@Table(name = "user_group", uniqueConstraints =
        @UniqueConstraint(name = "uq_user_group_tenant_name", columnNames = {"tenant_id", "name"}))
public class UserGroup {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(length = 512)
    private String description;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected UserGroup() {
    }

    public UserGroup(UUID id, String tenantId, String name, String description) {
        this.id = id;
        this.tenantId = tenantId;
        this.name = name;
        this.description = description;
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
