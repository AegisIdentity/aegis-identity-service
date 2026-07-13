package io.aegis.identity.web;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.service.AuthOutcome;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.UUID;

/** Request/response payloads for the user API. */
public final class UserDtos {

    private UserDtos() {
    }

    public record CreateUserRequest(
            @NotBlank @Size(max = 128) String username,
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 8, max = 200) String password) {
    }

    public record UserResponse(UUID id, String tenantId, String username, String email, String status) {
        public static UserResponse from(AppUser u) {
            return new UserResponse(u.getId(), u.getTenantId(), u.getUsername(), u.getEmail(),
                    u.getStatus().name());
        }
    }

    /** Tenant is supplied explicitly because the caller (authorization-server) knows it and uses a
     * client-credentials token that is not itself tied to one end-user tenant. */
    public record AuthenticateRequest(
            @NotBlank String tenantId,
            @NotBlank String username,
            @NotBlank String password) {
    }

    public record AuthenticateResponse(AuthOutcome outcome, UUID userId) {
    }
}
