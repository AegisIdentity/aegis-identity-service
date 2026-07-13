package io.aegis.identity.web;

import io.aegis.identity.domain.AuthPolicy;
import io.aegis.identity.service.AuthPolicyService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Per-tenant authentication policy. {@code GET/PUT /api/v1/auth-policy}, gated by {@code SCOPE_tenant:admin};
 * the tenant is taken from the caller's token so an admin only manages their own organization's policy.
 */
@RestController
public class AuthPolicyController {

    private final AuthPolicyService service;

    public AuthPolicyController(AuthPolicyService service) {
        this.service = service;
    }

    public record PolicyView(
            int passwordMinLength, boolean passwordRequireUppercase, boolean passwordRequireLowercase,
            boolean passwordRequireDigit, boolean passwordRequireSymbol,
            int lockoutThreshold, int lockoutDurationMinutes,
            boolean mfaRequired, int sessionTtlMinutes) {

        static PolicyView from(AuthPolicy p) {
            return new PolicyView(p.getPasswordMinLength(), p.isPasswordRequireUppercase(),
                    p.isPasswordRequireLowercase(), p.isPasswordRequireDigit(), p.isPasswordRequireSymbol(),
                    p.getLockoutThreshold(), p.getLockoutDurationMinutes(),
                    p.isMfaRequired(), p.getSessionTtlMinutes());
        }
    }

    public record PolicyUpdate(
            @Min(8) @Max(128) int passwordMinLength,
            boolean passwordRequireUppercase, boolean passwordRequireLowercase,
            boolean passwordRequireDigit, boolean passwordRequireSymbol,
            @Min(1) @Max(100) int lockoutThreshold,
            @Min(1) @Max(1440) int lockoutDurationMinutes,
            boolean mfaRequired,
            @Min(5) @Max(1440) int sessionTtlMinutes) {
    }

    @GetMapping("/api/v1/auth-policy")
    public PolicyView get(@AuthenticationPrincipal Jwt caller) {
        return PolicyView.from(service.effectivePolicy(tenantOf(caller)));
    }

    @PutMapping("/api/v1/auth-policy")
    public PolicyView update(@Valid @RequestBody PolicyUpdate body, @AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        AuthPolicy incoming = new AuthPolicy(tenant);
        incoming.setPasswordMinLength(body.passwordMinLength());
        incoming.setPasswordRequireUppercase(body.passwordRequireUppercase());
        incoming.setPasswordRequireLowercase(body.passwordRequireLowercase());
        incoming.setPasswordRequireDigit(body.passwordRequireDigit());
        incoming.setPasswordRequireSymbol(body.passwordRequireSymbol());
        incoming.setLockoutThreshold(body.lockoutThreshold());
        incoming.setLockoutDurationMinutes(body.lockoutDurationMinutes());
        incoming.setMfaRequired(body.mfaRequired());
        incoming.setSessionTtlMinutes(body.sessionTtlMinutes());
        return PolicyView.from(service.update(tenant, incoming));
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
