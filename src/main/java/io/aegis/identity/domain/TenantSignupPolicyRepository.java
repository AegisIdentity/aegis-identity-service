package io.aegis.identity.domain;

import org.springframework.data.jpa.repository.JpaRepository;

/** Persistence for {@link TenantSignupPolicy}, keyed by tenant id. */
public interface TenantSignupPolicyRepository extends JpaRepository<TenantSignupPolicy, String> {
}
