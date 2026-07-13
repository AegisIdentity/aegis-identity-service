package io.aegis.identity.domain;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GroupMembershipRepository extends JpaRepository<GroupMembership, UUID> {

    List<GroupMembership> findByGroupId(UUID groupId);

    boolean existsByGroupIdAndUserId(UUID groupId, UUID userId);

    long countByGroupId(UUID groupId);

    void deleteByGroupIdAndUserId(UUID groupId, UUID userId);

    void deleteByGroupId(UUID groupId);
}
