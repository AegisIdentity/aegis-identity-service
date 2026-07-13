package io.aegis.identity.domain;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * All finders are <strong>tenant-scoped</strong> by construction. There is intentionally no
 * {@code findById(id)} exposed to callers — every read must carry a tenant to preserve isolation
 * (see ARCHITECTURE.md §5.2). A cross-tenant read is a Sev-1, so the API makes it hard to write one.
 */
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    List<AppUser> findByTenantIdOrderByUsername(String tenantId);

    Optional<AppUser> findByTenantIdAndUsername(String tenantId, String username);

    Optional<AppUser> findByTenantIdAndEmail(String tenantId, String email);

    Optional<AppUser> findByTenantIdAndId(String tenantId, UUID id);

    boolean existsByTenantIdAndUsername(String tenantId, String username);

    boolean existsByTenantIdAndEmail(String tenantId, String email);
}
