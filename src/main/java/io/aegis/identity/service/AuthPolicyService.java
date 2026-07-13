package io.aegis.identity.service;

import io.aegis.identity.domain.AuthPolicy;
import io.aegis.identity.domain.AuthPolicyRepository;
import io.aegis.identity.service.UserExceptions.PasswordPolicyException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Per-tenant authentication policy: read (with defaults), update, and password-rule enforcement. The
 * password rules and lockout parameters here are enforced by {@link UserService}; {@code mfaRequired}
 * and {@code sessionTtlMinutes} are stored and surfaced for the console but enforced elsewhere.
 */
@Service
public class AuthPolicyService {

    private final AuthPolicyRepository policies;
    private final AuditService auditService;

    public AuthPolicyService(AuthPolicyRepository policies, AuditService auditService) {
        this.policies = policies;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public AuthPolicy effectivePolicy(String tenantId) {
        return policies.findById(tenantId).orElseGet(() -> AuthPolicy.defaults(tenantId));
    }

    @Transactional
    public AuthPolicy update(String tenantId, AuthPolicy incoming) {
        AuthPolicy policy = policies.findById(tenantId).orElseGet(() -> new AuthPolicy(tenantId));
        policy.setPasswordMinLength(clamp(incoming.getPasswordMinLength(), 8, 128));
        policy.setPasswordRequireUppercase(incoming.isPasswordRequireUppercase());
        policy.setPasswordRequireLowercase(incoming.isPasswordRequireLowercase());
        policy.setPasswordRequireDigit(incoming.isPasswordRequireDigit());
        policy.setPasswordRequireSymbol(incoming.isPasswordRequireSymbol());
        policy.setLockoutThreshold(clamp(incoming.getLockoutThreshold(), 1, 100));
        policy.setLockoutDurationMinutes(clamp(incoming.getLockoutDurationMinutes(), 1, 1440));
        policy.setMfaRequired(incoming.isMfaRequired());
        policy.setSessionTtlMinutes(clamp(incoming.getSessionTtlMinutes(), 5, 1440));
        policy.touch();
        AuthPolicy saved = policies.save(policy);
        auditService.record(tenantId, "system", "POLICY_UPDATED", null, null);
        return saved;
    }

    /** Enforces the tenant's password rules; throws {@link PasswordPolicyException} on violation. */
    public void validatePassword(String tenantId, String rawPassword) {
        AuthPolicy p = effectivePolicy(tenantId);
        List<String> problems = new ArrayList<>();
        if (rawPassword == null || rawPassword.length() < p.getPasswordMinLength()) {
            problems.add("at least " + p.getPasswordMinLength() + " characters");
        }
        String pw = rawPassword == null ? "" : rawPassword;
        if (p.isPasswordRequireUppercase() && pw.chars().noneMatch(Character::isUpperCase)) {
            problems.add("an uppercase letter");
        }
        if (p.isPasswordRequireLowercase() && pw.chars().noneMatch(Character::isLowerCase)) {
            problems.add("a lowercase letter");
        }
        if (p.isPasswordRequireDigit() && pw.chars().noneMatch(Character::isDigit)) {
            problems.add("a digit");
        }
        if (p.isPasswordRequireSymbol() && pw.chars().allMatch(Character::isLetterOrDigit)) {
            problems.add("a symbol");
        }
        if (!problems.isEmpty()) {
            throw new PasswordPolicyException("password must contain " + String.join(", ", problems));
        }
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
