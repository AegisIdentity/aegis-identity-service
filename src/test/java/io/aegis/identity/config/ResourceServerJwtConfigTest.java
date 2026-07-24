package io.aegis.identity.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * L-core-3: audience validation is a no-op scaffold when {@code aegis.jwt.expected-audience} is unset,
 * and enforces membership once configured. Proves the mechanism actually gates when switched on.
 */
class ResourceServerJwtConfigTest {

    private static Jwt jwtWithAudience(List<String> aud) {
        Jwt.Builder b = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("s")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("scope", "identity:users:read");
        if (aud != null) {
            b.audience(aud);
        }
        return b.build();
    }

    @Test
    void unset_expected_audience_is_a_no_op_and_accepts_any_token() {
        OAuth2TokenValidator<Jwt> validator = ResourceServerJwtConfig.audienceValidator("");
        assertThat(validator.validate(jwtWithAudience(null)).hasErrors()).isFalse();
        assertThat(validator.validate(jwtWithAudience(List.of("anything"))).hasErrors()).isFalse();
    }

    @Test
    void configured_expected_audience_accepts_a_matching_aud_and_rejects_a_mismatch() {
        OAuth2TokenValidator<Jwt> validator = ResourceServerJwtConfig.audienceValidator("aegis-identity-service");
        assertThat(validator.validate(jwtWithAudience(List.of("aegis-identity-service", "x")))
                .hasErrors()).isFalse();
        assertThat(validator.validate(jwtWithAudience(List.of("aegis-internal"))).hasErrors()).isTrue();
        assertThat(validator.validate(jwtWithAudience(null)).hasErrors()).isTrue();
    }
}
