package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * A user account. Always scoped to a {@code tenantId}; uniqueness of username/email is
 * <em>per tenant</em>, never global — two tenants may each have a user "admin".
 *
 * <p>{@code passwordHash} holds an Argon2id-encoded hash (never a plaintext or reversible value).
 */
@Entity
@Table(name = "app_user", uniqueConstraints = {
        @UniqueConstraint(name = "uq_app_user_tenant_username", columnNames = {"tenant_id", "username"}),
        @UniqueConstraint(name = "uq_app_user_tenant_email", columnNames = {"tenant_id", "email"})
})
public class AppUser {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(nullable = false, length = 128)
    private String username;

    @Column(nullable = false, length = 320)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 512)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected AppUser() {
    }

    public AppUser(UUID id, String tenantId, String username, String email, String passwordHash) {
        this.id = id;
        this.tenantId = tenantId;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
        touch();
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
        touch();
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void recordFailedLogin(int lockThreshold, java.time.Duration lockDuration, Instant now) {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= lockThreshold) {
            this.status = UserStatus.LOCKED;
            this.lockedUntil = now.plus(lockDuration);
        }
        touch();
    }

    public void recordSuccessfulLogin() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
        if (this.status == UserStatus.LOCKED) {
            this.status = UserStatus.ACTIVE;
        }
        touch();
    }

    public boolean isCurrentlyLocked(Instant now) {
        return status == UserStatus.LOCKED && lockedUntil != null && lockedUntil.isAfter(now);
    }

    private void touch() {
        this.updatedAt = Instant.now();
    }
}
