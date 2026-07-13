package io.aegis.identity.domain;

import org.springframework.data.jpa.repository.JpaRepository;

/** Persistence for {@link TenantBranding}, keyed by tenant id. */
public interface TenantBrandingRepository extends JpaRepository<TenantBranding, String> {
}
