package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.UUID;

/** Membership of a user in a group. Tenant-scoped; a user is in a group at most once. */
@Entity
@Table(name = "group_membership", uniqueConstraints =
        @UniqueConstraint(name = "uq_group_membership", columnNames = {"group_id", "user_id"}))
public class GroupMembership {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(name = "group_id", nullable = false, updatable = false)
    private UUID groupId;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    protected GroupMembership() {
    }

    public GroupMembership(UUID id, String tenantId, UUID groupId, UUID userId) {
        this.id = id;
        this.tenantId = tenantId;
        this.groupId = groupId;
        this.userId = userId;
    }

    public UUID getId() {
        return id;
    }

    public UUID getGroupId() {
        return groupId;
    }

    public UUID getUserId() {
        return userId;
    }
}
