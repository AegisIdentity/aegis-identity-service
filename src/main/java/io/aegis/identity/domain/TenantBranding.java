package io.aegis.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Per-tenant sign-in branding. Public (shown before authentication on the login page). Text fields and
 * a primary color are applied by the authorization-server's login page; the color is delivered as a
 * same-origin theme stylesheet so it stays within the login page's strict CSP. A custom logo needs
 * asset hosting + an img-src allowance and is a documented follow-up.
 */
@Entity
@Table(name = "tenant_branding")
public class TenantBranding {

    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(name = "product_name", nullable = false, length = 64)
    private String productName = "Aegis Identity";

    @Column(name = "sign_in_heading", nullable = false, length = 160)
    private String signInHeading = "One secure front door for every app.";

    @Column(name = "sign_in_subtitle", nullable = false, length = 280)
    private String signInSubtitle =
            "Sign in once and Aegis handles password, passkey, MFA, social, and SAML for your whole organization.";

    /** Hex color, e.g. {@code #3b5bdb}. Validated on write. */
    @Column(name = "primary_color", nullable = false, length = 7)
    private String primaryColor = "#3b5bdb";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected TenantBranding() {
    }

    public TenantBranding(String tenantId) {
        this.tenantId = tenantId;
    }

    public static TenantBranding defaults(String tenantId) {
        return new TenantBranding(tenantId);
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getSignInHeading() {
        return signInHeading;
    }

    public void setSignInHeading(String signInHeading) {
        this.signInHeading = signInHeading;
    }

    public String getSignInSubtitle() {
        return signInSubtitle;
    }

    public void setSignInSubtitle(String signInSubtitle) {
        this.signInSubtitle = signInSubtitle;
    }

    public String getPrimaryColor() {
        return primaryColor;
    }

    public void setPrimaryColor(String primaryColor) {
        this.primaryColor = primaryColor;
    }
}
