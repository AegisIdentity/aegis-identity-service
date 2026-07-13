package io.aegis.identity.domain;

import org.springframework.data.jpa.repository.JpaRepository;

/** Persistence for {@link AuthPolicy}, keyed by tenant id. */
public interface AuthPolicyRepository extends JpaRepository<AuthPolicy, String> {
}
