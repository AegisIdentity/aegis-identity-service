package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Per-tenant authentication policy. Absence of a row means "defaults". The password rules and lockout
 * settings are <strong>enforced</strong> (password validation on user creation; lockout in
 * {@code authenticate}); {@code mfaRequired} and {@code sessionTtlMinutes} are stored and surfaced but
 * their runtime enforcement is owned by the MFA service / session layer (noted as follow-up).
 */
@Entity
@Table(name = "auth_policy")
public class AuthPolicy {

    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(name = "password_min_length", nullable = false)
    private int passwordMinLength = 8;

    @Column(name = "password_require_uppercase", nullable = false)
    private boolean passwordRequireUppercase = false;

    @Column(name = "password_require_lowercase", nullable = false)
    private boolean passwordRequireLowercase = false;

    @Column(name = "password_require_digit", nullable = false)
    private boolean passwordRequireDigit = false;

    @Column(name = "password_require_symbol", nullable = false)
    private boolean passwordRequireSymbol = false;

    @Column(name = "lockout_threshold", nullable = false)
    private int lockoutThreshold = 5;

    @Column(name = "lockout_duration_minutes", nullable = false)
    private int lockoutDurationMinutes = 15;

    @Column(name = "mfa_required", nullable = false)
    private boolean mfaRequired = false;

    @Column(name = "session_ttl_minutes", nullable = false)
    private int sessionTtlMinutes = 60;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected AuthPolicy() {
    }

    public AuthPolicy(String tenantId) {
        this.tenantId = tenantId;
    }

    /** A transient defaults instance for a tenant with no stored policy. */
    public static AuthPolicy defaults(String tenantId) {
        return new AuthPolicy(tenantId);
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }

    public String getTenantId() {
        return tenantId;
    }

    public int getPasswordMinLength() {
        return passwordMinLength;
    }

    public void setPasswordMinLength(int passwordMinLength) {
        this.passwordMinLength = passwordMinLength;
    }

    public boolean isPasswordRequireUppercase() {
        return passwordRequireUppercase;
    }

    public void setPasswordRequireUppercase(boolean v) {
        this.passwordRequireUppercase = v;
    }

    public boolean isPasswordRequireLowercase() {
        return passwordRequireLowercase;
    }

    public void setPasswordRequireLowercase(boolean v) {
        this.passwordRequireLowercase = v;
    }

    public boolean isPasswordRequireDigit() {
        return passwordRequireDigit;
    }

    public void setPasswordRequireDigit(boolean v) {
        this.passwordRequireDigit = v;
    }

    public boolean isPasswordRequireSymbol() {
        return passwordRequireSymbol;
    }

    public void setPasswordRequireSymbol(boolean v) {
        this.passwordRequireSymbol = v;
    }

    public int getLockoutThreshold() {
        return lockoutThreshold;
    }

    public void setLockoutThreshold(int lockoutThreshold) {
        this.lockoutThreshold = lockoutThreshold;
    }

    public int getLockoutDurationMinutes() {
        return lockoutDurationMinutes;
    }

    public void setLockoutDurationMinutes(int lockoutDurationMinutes) {
        this.lockoutDurationMinutes = lockoutDurationMinutes;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public void setMfaRequired(boolean mfaRequired) {
        this.mfaRequired = mfaRequired;
    }

    public int getSessionTtlMinutes() {
        return sessionTtlMinutes;
    }

    public void setSessionTtlMinutes(int sessionTtlMinutes) {
        this.sessionTtlMinutes = sessionTtlMinutes;
    }
}
