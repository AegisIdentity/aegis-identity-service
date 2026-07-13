package io.aegis.identity.service;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.domain.GroupMembership;
import io.aegis.identity.domain.GroupMembershipRepository;
import io.aegis.identity.domain.GroupRepository;
import io.aegis.identity.domain.UserGroup;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Group lifecycle and membership, tenant-scoped throughout. */
@Service
public class GroupService {

    private final GroupRepository groups;
    private final GroupMembershipRepository memberships;
    private final AppUserRepository users;

    public GroupService(GroupRepository groups, GroupMembershipRepository memberships,
                        AppUserRepository users) {
        this.groups = groups;
        this.memberships = memberships;
        this.users = users;
    }

    public static class DuplicateGroupException extends RuntimeException {
        public DuplicateGroupException(String m) {
            super(m);
        }
    }

    public static class GroupNotFoundException extends RuntimeException {
        public GroupNotFoundException(String m) {
            super(m);
        }
    }

    @Transactional
    public UserGroup create(String tenantId, String name, String description) {
        requireTenant(tenantId);
        if (groups.existsByTenantIdAndName(tenantId, name)) {
            throw new DuplicateGroupException("group name already exists in tenant");
        }
        return groups.save(new UserGroup(UUID.randomUUID(), tenantId, name, description));
    }

    @Transactional(readOnly = true)
    public List<UserGroup> list(String tenantId) {
        requireTenant(tenantId);
        return groups.findByTenantIdOrderByName(tenantId);
    }

    @Transactional(readOnly = true)
    public UserGroup get(String tenantId, UUID groupId) {
        return require(tenantId, groupId);
    }

    public long memberCount(UUID groupId) {
        return memberships.countByGroupId(groupId);
    }

    @Transactional
    public void delete(String tenantId, UUID groupId) {
        UserGroup group = require(tenantId, groupId);
        memberships.deleteByGroupId(group.getId());
        groups.delete(group);
    }

    @Transactional
    public void addMember(String tenantId, UUID groupId, UUID userId) {
        require(tenantId, groupId);
        // The user must exist in this tenant (also enforces tenant isolation of membership).
        users.findByTenantIdAndId(tenantId, userId)
                .orElseThrow(() -> new UserNotFoundException("no such user in tenant"));
        if (!memberships.existsByGroupIdAndUserId(groupId, userId)) {
            memberships.save(new GroupMembership(UUID.randomUUID(), tenantId, groupId, userId));
        }
    }

    @Transactional
    public void removeMember(String tenantId, UUID groupId, UUID userId) {
        require(tenantId, groupId);
        memberships.deleteByGroupIdAndUserId(groupId, userId);
    }

    @Transactional(readOnly = true)
    public List<AppUser> listMembers(String tenantId, UUID groupId) {
        require(tenantId, groupId);
        return memberships.findByGroupId(groupId).stream()
                .flatMap(m -> users.findByTenantIdAndId(tenantId, m.getUserId()).stream())
                .toList();
    }

    private UserGroup require(String tenantId, UUID groupId) {
        requireTenant(tenantId);
        return groups.findByTenantIdAndId(tenantId, groupId)
                .orElseThrow(() -> new GroupNotFoundException("no such group in tenant"));
    }

    private static void requireTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
    }
}
