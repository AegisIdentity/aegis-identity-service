package io.aegis.identity.service;

import io.aegis.identity.domain.TenantBranding;
import io.aegis.identity.domain.TenantBrandingRepository;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/** Per-tenant sign-in branding: read (with defaults) and update, with input validation. */
@Service
public class BrandingService {

    private static final Pattern HEX_COLOR = Pattern.compile("^#[0-9a-fA-F]{6}$");

    private final TenantBrandingRepository branding;
    private final AuditService auditService;

    public BrandingService(TenantBrandingRepository branding, AuditService auditService) {
        this.branding = branding;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public TenantBranding effectiveBranding(String tenantId) {
        return branding.findById(tenantId).orElseGet(() -> TenantBranding.defaults(tenantId));
    }

    @Transactional
    public TenantBranding update(String tenantId, TenantBranding incoming) {
        if (!HEX_COLOR.matcher(incoming.getPrimaryColor() == null ? "" : incoming.getPrimaryColor()).matches()) {
            throw new IllegalArgumentException("primaryColor must be a hex color like #3b5bdb");
        }
        TenantBranding b = branding.findById(tenantId).orElseGet(() -> new TenantBranding(tenantId));
        if (StringUtils.hasText(incoming.getProductName())) {
            b.setProductName(incoming.getProductName());
        }
        if (StringUtils.hasText(incoming.getSignInHeading())) {
            b.setSignInHeading(incoming.getSignInHeading());
        }
        if (StringUtils.hasText(incoming.getSignInSubtitle())) {
            b.setSignInSubtitle(incoming.getSignInSubtitle());
        }
        b.setPrimaryColor(incoming.getPrimaryColor());
        b.touch();
        TenantBranding saved = branding.save(b);
        auditService.record(tenantId, "system", "BRANDING_UPDATED", null, null);
        return saved;
    }
}
