package io.aegis.identity.service;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.TenantSignupPolicy;
import io.aegis.identity.domain.TenantSignupPolicyRepository;
import io.aegis.identity.service.UserExceptions.SignupNotAvailableException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Self-service end-user sign-up, gated by a per-tenant opt-in policy. A tenant's customers can only
 * self-register when the tenant admin has enabled it; otherwise sign-up is closed and the response is
 * indistinguishable from "no such organization" (anti-enumeration).
 *
 * <p>Production hardening (out of scope here, noted for the roadmap): email verification before the
 * account is usable, rate limiting / CAPTCHA on the public endpoint, and optional allowed-email-domain
 * restrictions per tenant.
 */
@Service
public class SignupService {

    private final TenantSignupPolicyRepository policies;
    private final UserService userService;
    private final AuditService auditService;

    public SignupService(TenantSignupPolicyRepository policies, UserService userService,
                         AuditService auditService) {
        this.policies = policies;
        this.userService = userService;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public boolean isEnabled(String tenantId) {
        return policies.findById(tenantId).map(TenantSignupPolicy::isEnabled).orElse(false);
    }

    /** Enables/disables self-service sign-up for a tenant (called by that tenant's admin). */
    @Transactional
    public TenantSignupPolicy setEnabled(String tenantId, boolean enabled) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
        TenantSignupPolicy policy = policies.findById(tenantId)
                .orElseGet(() -> new TenantSignupPolicy(tenantId, enabled));
        policy.setEnabled(enabled);
        return policies.save(policy);
    }

    /**
     * Registers an end-user into an existing tenant, but only if that tenant has enabled self-service
     * sign-up. When it is not enabled (or the tenant is unknown) the same {@link SignupNotAvailableException}
     * is thrown, so a caller cannot distinguish a closed tenant from a non-existent one.
     */
    @Transactional
    public AppUser signup(String tenantId, String username, String email, String rawPassword) {
        if (!isEnabled(tenantId)) {
            throw new SignupNotAvailableException("self-service sign-up is not available for this organization");
        }
        AppUser user = userService.createUser(tenantId, username, email, rawPassword);
        auditService.record(tenantId, username, "SIGNUP", username, "self-service sign-up");
        return user;
    }
}
