package io.aegis.identity.web;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.TenantSignupPolicy;
import io.aegis.identity.service.SignupService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Self-service end-user sign-up.
 *
 * <ul>
 *   <li><b>Public</b> {@code POST /api/v1/signup} — a tenant's customer self-registers (no token).
 *       Succeeds only if that tenant has opted in.</li>
 *   <li><b>Admin</b> {@code GET/PUT /api/v1/signup-policy} — the tenant admin reads/toggles the opt-in.
 *       The tenant is taken from the admin's token, never from the request, so an admin can only ever
 *       change their own organization's policy.</li>
 * </ul>
 */
@RestController
public class SignupController {

    private final SignupService signupService;

    public SignupController(SignupService signupService) {
        this.signupService = signupService;
    }

    public record SignupRequest(
            @NotBlank @Size(max = 63) String tenantSlug,
            @NotBlank String username,
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8, max = 200) String password) {
    }

    public record SignupResponse(String tenant, String username) {
    }

    public record SignupPolicyView(String tenant, boolean signupEnabled) {
    }

    public record SignupPolicyUpdate(@NotNull Boolean enabled) {
    }

    @PostMapping("/api/v1/signup")
    public ResponseEntity<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        AppUser user = signupService.signup(
                request.tenantSlug(), request.username(), request.email(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new SignupResponse(user.getTenantId(), user.getUsername()));
    }

    @GetMapping("/api/v1/signup-policy")
    public SignupPolicyView getPolicy(@AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        return new SignupPolicyView(tenant, signupService.isEnabled(tenant));
    }

    @PutMapping("/api/v1/signup-policy")
    public SignupPolicyView setPolicy(@Valid @RequestBody SignupPolicyUpdate update,
                                      @AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        TenantSignupPolicy policy = signupService.setEnabled(tenant, update.enabled());
        return new SignupPolicyView(tenant, policy.isEnabled());
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
