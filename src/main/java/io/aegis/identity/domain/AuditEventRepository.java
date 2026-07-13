package io.aegis.identity.domain;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Audit-event reads are <strong>tenant-scoped</strong> by construction — every query carries a
 * tenant to preserve isolation. Newest-first, paged for the console's "System Log" page.
 */
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {

    List<AuditEvent> findByTenantIdOrderByCreatedAtDesc(String tenantId, Pageable pageable);
}
