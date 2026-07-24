package io.aegis.identity.web;

import io.aegis.identity.service.UserExceptions.DuplicateUserException;
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
        // M-core-2: this endpoint is public and unauthenticated, so it must not become a tenant-existence
        // oracle. Whether or not the organization already exists, we return the SAME neutral 202 Accepted
        // with the caller's own submitted values echoed back — an existing org is silently NOT modified
        // (no hijack), and the caller cannot distinguish "created" from "already exists" by status/body.
        try {
            userService.onboardTenant(
                    request.tenantSlug(), request.adminUsername(), request.adminEmail(), request.adminPassword());
        } catch (DuplicateUserException alreadyExists) {
            // Neutral: do not reveal that the organization (or an admin within it) already exists.
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(new OnboardResponse(request.tenantSlug(), request.adminUsername()));
    }
}
