package io.aegis.identity.agent;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Tenant-scoped by construction, like every other repository here — there is deliberately no finder
 * that takes an agent id without a tenant. A cross-tenant read is a Sev-1, so the API is shaped to
 * make writing one awkward rather than relying on reviewer vigilance.
 */
public interface AgentIdentityRepository extends JpaRepository<AgentIdentity, UUID> {

    List<AgentIdentity> findByTenantIdOrderByAgentId(String tenantId);

    Optional<AgentIdentity> findByTenantIdAndAgentId(String tenantId, String agentId);

    boolean existsByTenantIdAndAgentId(String tenantId, String agentId);

    List<AgentIdentity> findByTenantIdAndOwnerPrincipal(String tenantId, String ownerPrincipal);
}
