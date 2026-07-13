package io.aegis.identity.web;

import io.aegis.identity.domain.AuditEvent;
import io.aegis.identity.service.AuditService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * System-log (audit) read API for the console. {@code GET /api/v1/system-log}, gated by
 * {@code SCOPE_tenant:admin}; the tenant is taken from the caller's token so an admin only ever sees
 * their own organization's events. Newest-first.
 */
@RestController
public class SystemLogController {

    private final AuditService auditService;

    public SystemLogController(AuditService auditService) {
        this.auditService = auditService;
    }

    /** One audit event as surfaced to the console. {@code createdAt} serializes as ISO-8601. */
    public record SystemLogEvent(UUID id, String tenantId, String actor, String action,
                                 String target, String detail, Instant createdAt) {
        static SystemLogEvent from(AuditEvent e) {
            return new SystemLogEvent(e.getId(), e.getTenantId(), e.getActor(), e.getAction(),
                    e.getTarget(), e.getDetail(), e.getCreatedAt());
        }
    }

    @GetMapping("/api/v1/system-log")
    public List<SystemLogEvent> recent(@AuthenticationPrincipal Jwt caller,
                                       @RequestParam(name = "limit", defaultValue = "50") int limit) {
        String tenant = tenantOf(caller);
        return auditService.recent(tenant, limit).stream().map(SystemLogEvent::from).toList();
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
