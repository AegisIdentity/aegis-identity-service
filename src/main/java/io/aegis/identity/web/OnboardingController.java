package io.aegis.identity.web;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public onboarding: creates a new organization's first admin user. This is the entry point a signup
 * page calls (no token yet — a brand-new org has no credentials). Guarded so it only works for an
 * organization that has no users; SecurityConfig permits it.
 */
@RestController
public class OnboardingController {

    private final UserService userService;

    public OnboardingController(UserService userService) {
        this.userService = userService;
    }

    public record OnboardRequest(
            @NotBlank String organizationName,
            @NotBlank @Size(max = 63) String tenantSlug,
            @NotBlank String adminUsername,
            @NotBlank @Email String adminEmail,
            @NotBlank @Size(min = 8, max = 200) String adminPassword) {
    }

    public record OnboardResponse(String tenant, String adminUsername) {
    }

    @PostMapping("/api/v1/onboarding")
    public ResponseEntity<OnboardResponse> onboard(@Valid @RequestBody OnboardRequest request) {
        AppUser admin = userService.onboardTenant(
                request.tenantSlug(), request.adminUsername(), request.adminEmail(), request.adminPassword());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new OnboardResponse(admin.getTenantId(), admin.getUsername()));
    }
}
