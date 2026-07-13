package io.aegis.identity.service;

import io.aegis.identity.domain.AuditEvent;
import io.aegis.identity.domain.AuditEventRepository;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes and reads tenant-scoped audit events for the console's "System Log". Writes are
 * <strong>best-effort</strong>: {@link #record} never throws, so an audit failure can never break the
 * primary operation it is describing. Reads are newest-first with a clamped page size.
 *
 * <p>Audit details must never carry secrets (passwords, tokens, full assertions).
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    static final int DEFAULT_LIMIT = 50;
    static final int MAX_LIMIT = 200;

    private final AuditEventRepository events;

    public AuditService(AuditEventRepository events) {
        this.events = events;
    }

    /**
     * Best-effort audit write. Swallows and logs any failure at WARN so the caller's primary
     * operation is never affected by an audit-store problem.
     */
    @Transactional
    public void record(String tenantId, String actor, String action, String target, String detail) {
        try {
            if (tenantId == null || tenantId.isBlank() || action == null || action.isBlank()) {
                return; // nothing meaningful to record; never fail the caller
            }
            events.save(new AuditEvent(UUID.randomUUID(), tenantId,
                    actor == null || actor.isBlank() ? "system" : actor, action, target, detail));
        } catch (RuntimeException ex) {
            log.warn("audit write failed (action={}, tenant={}): {}", action, tenantId, ex.toString());
        }
    }

    /** Newest-first audit events for a tenant. {@code limit} defaults to 50 and is clamped to 200. */
    @Transactional(readOnly = true)
    public List<AuditEvent> recent(String tenantId, int limit) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
        int effective = limit <= 0 ? DEFAULT_LIMIT : Math.min(limit, MAX_LIMIT);
        return events.findByTenantIdOrderByCreatedAtDesc(tenantId, PageRequest.of(0, effective));
    }
}
