package io.aegis.identity.service;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.domain.UserStatus;
import io.aegis.identity.service.UserExceptions.DuplicateUserException;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * User lifecycle + credential verification, tenant-scoped throughout. This is the service the
 * authorization-server calls to verify a resource-owner's password (ARCHITECTURE.md §6.1).
 *
 * <p>Brute-force defense: after {@code lockThreshold} consecutive failures the account is locked for
 * {@code lockDuration}. Successful auth resets the counter. Verification never reveals whether a
 * username exists (always {@code BAD_CREDENTIALS}) to prevent enumeration.
 */
@Service
public class UserService {

    private final AppUserRepository users;
    private final PasswordHasher hasher;
    private final int lockThreshold;
    private final Duration lockDuration;

    public UserService(AppUserRepository users,
                       PasswordHasher hasher,
                       @Value("${aegis.identity.lockout.threshold:5}") int lockThreshold,
                       @Value("${aegis.identity.lockout.duration:PT15M}") Duration lockDuration) {
        this.users = users;
        this.hasher = hasher;
        this.lockThreshold = lockThreshold;
        this.lockDuration = lockDuration;
    }

    @Transactional
    public AppUser createUser(String tenantId, String username, String email, String rawPassword) {
        requireTenant(tenantId);
        if (users.existsByTenantIdAndUsername(tenantId, username)) {
            throw new DuplicateUserException("username already exists in tenant");
        }
        if (users.existsByTenantIdAndEmail(tenantId, email)) {
            throw new DuplicateUserException("email already exists in tenant");
        }
        AppUser user = new AppUser(UUID.randomUUID(), tenantId, username, email, hasher.hash(rawPassword));
        return users.save(user);
    }

    @Transactional(readOnly = true)
    public AppUser getUser(String tenantId, UUID id) {
        requireTenant(tenantId);
        return users.findByTenantIdAndId(tenantId, id)
                .orElseThrow(() -> new UserNotFoundException("no such user in tenant"));
    }

    /**
     * Verify a password. Locks the account after too many failures. All branches are constant in the
     * information they reveal about account existence.
     */
    @Transactional
    public AuthResult authenticate(String tenantId, String username, String rawPassword) {
        requireTenant(tenantId);
        Instant now = Instant.now();
        var maybeUser = users.findByTenantIdAndUsername(tenantId, username);
        if (maybeUser.isEmpty()) {
            return AuthResult.of(AuthOutcome.BAD_CREDENTIALS);
        }
        AppUser user = maybeUser.get();

        if (user.getStatus() == UserStatus.DISABLED) {
            return AuthResult.of(AuthOutcome.DISABLED);
        }
        if (user.isCurrentlyLocked(now)) {
            return AuthResult.of(AuthOutcome.LOCKED);
        }

        if (hasher.matches(rawPassword, user.getPasswordHash())) {
            user.recordSuccessfulLogin();
            users.save(user);
            return AuthResult.success(user.getId());
        }

        user.recordFailedLogin(lockThreshold, lockDuration, now);
        users.save(user);
        return AuthResult.of(user.isCurrentlyLocked(now) ? AuthOutcome.LOCKED : AuthOutcome.BAD_CREDENTIALS);
    }

    private static void requireTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
    }
}
