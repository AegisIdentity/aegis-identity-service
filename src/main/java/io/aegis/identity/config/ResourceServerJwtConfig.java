package io.aegis.identity.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Resource-server JWT decoder that survives the Dockerized split-horizon issuer problem.
 *
 * <p>The browser reaches the authorization-server on a public host (e.g. {@code http://localhost:9000}),
 * so the tokens it presents carry that issuer — but this service runs inside the network where that
 * host is not resolvable, and the AS's own service tokens carry the in-network issuer
 * ({@code http://authorization-server:9000}). A single {@code issuer-uri} cannot satisfy both.
 *
 * <p>So keys are always fetched from a reachable in-network JWKS URI, and the issuer claim is validated
 * against an <em>allowlist</em> of trusted issuers (exact match, or a {@code /tenant} sub-path of one —
 * forward-compatible with per-tenant issuers). Signature and expiry are still enforced; only the
 * hostname the token was minted behind is treated flexibly. Production (single ingress host, real DNS)
 * collapses the allowlist to one issuer.
 */
@Configuration(proxyBeanMethods = false)
public class ResourceServerJwtConfig {

    @Bean
    public JwtDecoder jwtDecoder(
            @Value("${aegis.jwt.jwk-set-uri:http://localhost:9000/oauth2/jwks}") String jwkSetUri,
            @Value("${aegis.jwt.accepted-issuers:http://localhost:9000,http://authorization-server:9000}")
            List<String> acceptedIssuers) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                issuerAllowlistValidator(List.copyOf(acceptedIssuers))));
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> issuerAllowlistValidator(List<String> acceptedIssuers) {
        return jwt -> {
            String iss = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            boolean ok = iss != null && acceptedIssuers.stream()
                    .anyMatch(base -> iss.equals(base) || iss.startsWith(base + "/"));
            return ok ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                            "issuer not accepted: " + iss, null));
        };
    }
}
