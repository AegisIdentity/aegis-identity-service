package io.aegis.identity.web;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.UserStatus;
import io.aegis.identity.service.AuthResult;
import io.aegis.identity.service.UserService;
import io.aegis.identity.web.UserDtos.AuthenticateRequest;
import io.aegis.identity.web.UserDtos.AuthenticateResponse;
import io.aegis.identity.web.UserDtos.CreateUserRequest;
import io.aegis.identity.web.UserDtos.UserResponse;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * User API. Authorization is enforced by scope in {@code SecurityConfig}; the acting tenant for
 * user-facing operations is taken from the caller's {@code tenant} token claim — never from the
 * request body — so a caller cannot act outside its own tenant.
 */
@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/api/v1/users")
    public ResponseEntity<UserResponse> create(@AuthenticationPrincipal Jwt jwt,
                                               @Valid @RequestBody CreateUserRequest request) {
        String tenantId = tenantOf(jwt);
        AppUser user = userService.createUser(tenantId, request.username(), request.email(),
                request.password());
        return ResponseEntity.created(URI.create("/api/v1/users/" + user.getId()))
                .body(UserResponse.from(user));
    }

    @GetMapping("/api/v1/users")
    public List<UserResponse> list(@AuthenticationPrincipal Jwt jwt) {
        return userService.listUsers(tenantOf(jwt)).stream().map(UserResponse::from).toList();
    }

    @GetMapping("/api/v1/users/{id}")
    public UserResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        return UserResponse.from(userService.getUser(tenantOf(jwt), id));
    }

    @PostMapping("/api/v1/users/{id}/disable")
    public UserResponse disable(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        return UserResponse.from(userService.setStatus(tenantOf(jwt), id, UserStatus.DISABLED));
    }

    @PostMapping("/api/v1/users/{id}/enable")
    public UserResponse enable(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        return UserResponse.from(userService.setStatus(tenantOf(jwt), id, UserStatus.ACTIVE));
    }

    @DeleteMapping("/api/v1/users/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        userService.deleteUser(tenantOf(jwt), id);
        return ResponseEntity.noContent().build();
    }

    /** Credential verification for the authorization-server. Tenant comes from the request body. */
    @PostMapping("/api/v1/users:authenticate")
    public AuthenticateResponse authenticate(@Valid @RequestBody AuthenticateRequest request) {
        AuthResult result = userService.authenticate(request.tenantId(), request.username(),
                request.password());
        return new AuthenticateResponse(result.outcome(), result.userId());
    }

    private static String tenantOf(Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("token is missing the required 'tenant' claim");
        }
        return tenant;
    }
}
