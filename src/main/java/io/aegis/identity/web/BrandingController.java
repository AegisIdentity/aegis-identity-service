package io.aegis.identity.web;

import io.aegis.identity.domain.TenantBranding;
import io.aegis.identity.service.BrandingService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Per-tenant sign-in branding.
 * <ul>
 *   <li><b>Public</b> {@code GET /api/v1/branding/{tenant}} — the login page reads it before auth.</li>
 *   <li><b>Admin</b> {@code PUT /api/v1/branding} — the tenant admin sets it (tenant from the token).</li>
 * </ul>
 */
@RestController
public class BrandingController {

    private final BrandingService service;

    public BrandingController(BrandingService service) {
        this.service = service;
    }

    public record BrandingView(String tenant, String productName, String signInHeading,
                               String signInSubtitle, String primaryColor) {
        static BrandingView from(TenantBranding b) {
            return new BrandingView(b.getTenantId(), b.getProductName(), b.getSignInHeading(),
                    b.getSignInSubtitle(), b.getPrimaryColor());
        }
    }

    public record BrandingUpdate(
            @NotBlank @Size(max = 64) String productName,
            @NotBlank @Size(max = 160) String signInHeading,
            @NotBlank @Size(max = 280) String signInSubtitle,
            @NotBlank @Pattern(regexp = "^#[0-9a-fA-F]{6}$", message = "hex color like #3b5bdb")
            String primaryColor) {
    }

    /** Public: the login page reads a tenant's branding before authentication. */
    @GetMapping("/api/v1/branding/{tenant}")
    public BrandingView get(@PathVariable String tenant) {
        return BrandingView.from(service.effectiveBranding(tenant));
    }

    /** Admin: the console reads its own tenant's branding (tenant from the token). */
    @GetMapping("/api/v1/branding")
    public BrandingView getOwn(@AuthenticationPrincipal Jwt caller) {
        return BrandingView.from(service.effectiveBranding(tenantOf(caller)));
    }

    @PutMapping("/api/v1/branding")
    public BrandingView update(@Valid @RequestBody BrandingUpdate body, @AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        TenantBranding incoming = new TenantBranding(tenant);
        incoming.setProductName(body.productName());
        incoming.setSignInHeading(body.signInHeading());
        incoming.setSignInSubtitle(body.signInSubtitle());
        incoming.setPrimaryColor(body.primaryColor());
        return BrandingView.from(service.update(tenant, incoming));
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
