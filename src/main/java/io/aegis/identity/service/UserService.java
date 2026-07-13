package io.aegis.identity.service;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.domain.UserStatus;
import io.aegis.identity.service.UserExceptions.DuplicateUserException;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
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

    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");

    /**
     * Bootstraps a new organization's first admin user. Public onboarding path: allowed only when the
     * tenant has no users yet, so it can't hijack an existing organization. (Production hardens this
     * further with an email-verified signup token + rate limiting.)
     */
    @Transactional
    public AppUser onboardTenant(String tenantSlug, String username, String email, String rawPassword) {
        if (tenantSlug == null || !SLUG.matcher(tenantSlug).matches()) {
            throw new IllegalArgumentException("organization must be a lowercase DNS-safe slug");
        }
        if (!users.findByTenantIdOrderByUsername(tenantSlug).isEmpty()) {
            throw new UserExceptions.DuplicateUserException(
                    "organization already exists; onboarding is only for a new organization");
        }
        return createUser(tenantSlug, username, email, rawPassword);
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

    @Transactional(readOnly = true)
    public List<AppUser> listUsers(String tenantId) {
        requireTenant(tenantId);
        return users.findByTenantIdOrderByUsername(tenantId);
    }

    /** Enable (ACTIVE, clearing any lockout) or disable a user. */
    @Transactional
    public AppUser setStatus(String tenantId, UUID id, UserStatus status) {
        AppUser user = getUser(tenantId, id);
        if (status == UserStatus.ACTIVE) {
            user.recordSuccessfulLogin(); // clears failed-attempt / lockout counters
        }
        user.setStatus(status); // apply the requested status (works from DISABLED or LOCKED)
        return users.save(user);
    }

    @Transactional
    public void deleteUser(String tenantId, UUID id) {
        users.delete(getUser(tenantId, id));
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
