package io.aegis.identity.domain;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GroupRepository extends JpaRepository<UserGroup, UUID> {

    List<UserGroup> findByTenantIdOrderByName(String tenantId);

    Optional<UserGroup> findByTenantIdAndId(String tenantId, UUID id);

    boolean existsByTenantIdAndName(String tenantId, String name);
}
