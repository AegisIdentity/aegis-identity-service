package io.aegis.identity.service;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.domain.AuthPolicy;
import io.aegis.identity.domain.UserStatus;
import io.aegis.identity.service.UserExceptions.DuplicateUserException;
import io.aegis.identity.service.UserExceptions.IncorrectPasswordException;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
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
    private final AuthPolicyService authPolicyService;
    private final AuditService auditService;

    /**
     * A precomputed valid Argon2id hash of a random value (M-core-1). On the username-not-found path we
     * verify the supplied password against this dummy so the request performs the same slow Argon2id
     * work as the found path — making unknown-user and wrong-password indistinguishable by latency
     * (anti-enumeration). Computed once at construction so it is a stable constant for the JVM lifetime.
     */
    private final String dummyPasswordHash;

    public UserService(AppUserRepository users, PasswordHasher hasher, AuthPolicyService authPolicyService,
                       AuditService auditService) {
        this.users = users;
        this.hasher = hasher;
        this.authPolicyService = authPolicyService;
        this.auditService = auditService;
        this.dummyPasswordHash = hasher.hash("aegis-timing-guard:" + UUID.randomUUID());
    }

    private static final Pattern SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,62}$");

    /**
     * Bootstraps a new organization's first admin user. Public onboarding path: allowed only when the
     * tenant has no users yet, so it can't hijack an existing organization.
     *
     * <p>M-core-2: this method is reached from the public, unauthenticated {@code POST /api/v1/onboarding}
     * endpoint. The status/body oracle is closed in the controller (neutral 202 either way). This method
     * closes the residual <em>timing</em> oracle: the new-org path runs a slow Argon2id hash (inside
     * {@link #createUser}), while the existing-org path would otherwise throw immediately with no hashing —
     * so an attacker could time the response to learn whether an org/slug exists. We equalize the work by
     * running the same Argon2id verification against the dummy hash on every duplicate path (mirrors the
     * M-core-1 anti-enumeration guard in {@link #authenticate}). The try/catch guarantees the hash runs no
     * matter where the {@link DuplicateUserException} is raised (org-already-exists here, or a
     * username/email collision inside {@code createUser}), so all outcomes cost the same wall-clock time.
     *
     * <p>Note: the new-org path also runs {@link AuthPolicyService#validatePassword} inside
     * {@code createUser}, which the existing-org path never reaches. This is NOT an oracle for a
     * genuinely-new org: such an org has no stored policy row (a row can only be written by an
     * authenticated admin, which requires a pre-existing user), so it falls back to the default policy
     * — length ≥ 8 with no complexity rules — which is exactly the controller's {@code @Size(min=8)}
     * bean-validation constraint. Any password that reaches this method has therefore already satisfied
     * the default policy, so {@code validatePassword} cannot diverge here. (The sole residual is a stale
     * strict policy row on a slug whose users were all later deleted — not attacker-controllable, and
     * such a slug is not a "fresh" org anyway; left as accepted residual.)
     *
     * <p>TODO(security) M-core-2: the fuller defense-in-depth is rate limiting / CAPTCHA on this public
     * endpoint plus an email-verified onboarding token so an unauthenticated caller cannot probe org
     * existence at scale. No rate-limit hook exists in this service yet — this change closes only the
     * timing oracle; the throttle + verified-token remain as follow-up hardening.
     */
    @Transactional
    public AppUser onboardTenant(String tenantSlug, String username, String email, String rawPassword) {
        if (tenantSlug == null || !SLUG.matcher(tenantSlug).matches()) {
            throw new IllegalArgumentException("organization must be a lowercase DNS-safe slug");
        }
        try {
            if (!users.findByTenantIdOrderByUsername(tenantSlug).isEmpty()) {
                throw new UserExceptions.DuplicateUserException(
                        "organization already exists; onboarding is only for a new organization");
            }
            return createUser(tenantSlug, username, email, rawPassword);
        } catch (DuplicateUserException duplicate) {
            // Pay the same Argon2id cost as the create path before propagating, so the existing-org
            // (and username/email-collision) path is indistinguishable from a fresh org by latency.
            // The result is deliberately discarded — it is only here to burn the equivalent CPU/memory.
            hasher.matches(rawPassword, dummyPasswordHash);
            throw duplicate;
        }
    }

    /**
     * Find-or-create a user for a federated (social/OIDC/SAML) login. Matching is by email — the stable
     * identifier across providers — so a returning user is linked to their existing account rather than
     * duplicated. A newly provisioned user gets an unusable random password (they authenticate through
     * the external IdP, never by password here).
     */
    @Transactional
    public AppUser provisionFederatedUser(String tenantId, String email, String preferredUsername) {
        requireTenant(tenantId);
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required to provision a federated user");
        }
        return users.findByTenantIdAndEmail(tenantId, email).orElseGet(() -> {
            String username = (preferredUsername == null || preferredUsername.isBlank())
                    ? email : preferredUsername;
            if (users.existsByTenantIdAndUsername(tenantId, username)) {
                username = email; // fall back to the (unique) email if the preferred handle is taken
            }
            String unusablePassword = UUID.randomUUID() + ":" + UUID.randomUUID();
            AppUser user = new AppUser(UUID.randomUUID(), tenantId, username, email,
                    hasher.hash(unusablePassword));
            return users.save(user);
        });
    }

    @Transactional
    public AppUser createUser(String tenantId, String username, String email, String rawPassword) {
        requireTenant(tenantId);
        authPolicyService.validatePassword(tenantId, rawPassword); // enforce the tenant's password policy
        if (users.existsByTenantIdAndUsername(tenantId, username)) {
            throw new DuplicateUserException("username already exists in tenant");
        }
        if (users.existsByTenantIdAndEmail(tenantId, email)) {
            throw new DuplicateUserException("email already exists in tenant");
        }
        AppUser user = new AppUser(UUID.randomUUID(), tenantId, username, email, hasher.hash(rawPassword));
        AppUser saved = users.save(user);
        auditService.record(tenantId, "system", "USER_CREATED", username, null);
        return saved;
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
        AppUser saved = users.save(user);
        auditService.record(tenantId, "system",
                status == UserStatus.DISABLED ? "USER_DISABLED" : "USER_ENABLED",
                user.getUsername(), null);
        return saved;
    }

    @Transactional
    public void deleteUser(String tenantId, UUID id) {
        AppUser user = getUser(tenantId, id);
        users.delete(user);
        auditService.record(tenantId, "system", "USER_DELETED", user.getUsername(), null);
    }

    /**
     * Self-service password change. Resolves the caller's own account within the tenant (by id when the
     * caller's subject is a UUID, otherwise by username), verifies the {@code currentPassword} against the
     * stored Argon2 hash, enforces the tenant password policy on {@code newPassword}, and persists the new
     * credential. Never reveals anything beyond a generic "current password is incorrect" on a mismatch.
     *
     * @param subjectOrUsername the token subject (a UUID in production) or, failing that, the username
     */
    @Transactional
    public void changeOwnPassword(String tenantId, String subjectOrUsername, String preferredUsername,
                                  String currentPassword, String newPassword) {
        requireTenant(tenantId);
        AppUser user = resolveSelf(tenantId, subjectOrUsername, preferredUsername);
        if (!hasher.matches(currentPassword, user.getPasswordHash())) {
            throw new IncorrectPasswordException("current password is incorrect");
        }
        authPolicyService.validatePassword(tenantId, newPassword); // enforce the tenant's password policy
        user.setPasswordHash(hasher.hash(newPassword));
        users.save(user);
        auditService.record(tenantId, user.getUsername(), "PASSWORD_CHANGED", user.getUsername(), null);
    }

    /**
     * Resolves the caller's own {@link AppUser} within the tenant. Prefers a lookup by id when the token
     * subject is a UUID (production shape); falls back to {@code preferredUsername}, then to the raw
     * subject as a username. All lookups are tenant-scoped, so a caller can never reach another tenant.
     */
    private AppUser resolveSelf(String tenantId, String subjectOrUsername, String preferredUsername) {
        if (subjectOrUsername != null && !subjectOrUsername.isBlank()) {
            Optional<UUID> asUuid = tryParseUuid(subjectOrUsername);
            if (asUuid.isPresent()) {
                Optional<AppUser> byId = users.findByTenantIdAndId(tenantId, asUuid.get());
                if (byId.isPresent()) {
                    return byId.get();
                }
            }
        }
        if (preferredUsername != null && !preferredUsername.isBlank()) {
            Optional<AppUser> byPreferred = users.findByTenantIdAndUsername(tenantId, preferredUsername);
            if (byPreferred.isPresent()) {
                return byPreferred.get();
            }
        }
        if (subjectOrUsername != null && !subjectOrUsername.isBlank()) {
            Optional<AppUser> bySubject = users.findByTenantIdAndUsername(tenantId, subjectOrUsername);
            if (bySubject.isPresent()) {
                return bySubject.get();
            }
        }
        throw new UserNotFoundException("no such user in tenant");
    }

    private static Optional<UUID> tryParseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /**
     * Verify a password. Locks the account after too many failures. All branches are constant in the
     * information they reveal about account existence.
     */
    @Transactional
    public AuthResult authenticate(String tenantId, String username, String rawPassword) {
        requireTenant(tenantId);
        AuthPolicy policy = authPolicyService.effectivePolicy(tenantId);
        Instant now = Instant.now();
        var maybeUser = users.findByTenantIdAndUsername(tenantId, username);
        if (maybeUser.isEmpty()) {
            // M-core-1: run the same Argon2id verification against a dummy hash and discard the result,
            // so an unknown username costs the same wall-clock time as a wrong password (no enumeration
            // by timing). The outcome is deliberately ignored — it is always false.
            hasher.matches(rawPassword, dummyPasswordHash);
            auditService.record(tenantId, username, "AUTH_FAILURE", username, "bad credentials");
            return AuthResult.of(AuthOutcome.BAD_CREDENTIALS);
        }
        AppUser user = maybeUser.get();

        if (user.getStatus() == UserStatus.DISABLED) {
            auditService.record(tenantId, username, "AUTH_FAILURE", username, "disabled");
            return AuthResult.of(AuthOutcome.DISABLED);
        }
        if (user.isCurrentlyLocked(now)) {
            auditService.record(tenantId, username, "AUTH_FAILURE", username, "locked");
            return AuthResult.of(AuthOutcome.LOCKED);
        }

        if (hasher.matches(rawPassword, user.getPasswordHash())) {
            user.recordSuccessfulLogin();
            users.save(user);
            auditService.record(tenantId, username, "AUTH_SUCCESS", username, null);
            return AuthResult.success(user.getId());
        }

        user.recordFailedLogin(policy.getLockoutThreshold(),
                Duration.ofMinutes(policy.getLockoutDurationMinutes()), now);
        users.save(user);
        boolean nowLocked = user.isCurrentlyLocked(now);
        auditService.record(tenantId, username, "AUTH_FAILURE", username,
                nowLocked ? "locked" : "bad credentials");
        return AuthResult.of(nowLocked ? AuthOutcome.LOCKED : AuthOutcome.BAD_CREDENTIALS);
    }

    private static void requireTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
    }
}
