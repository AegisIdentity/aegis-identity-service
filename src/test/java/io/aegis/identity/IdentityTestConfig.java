package io.aegis.identity;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Test infrastructure: a real Postgres, and a stub {@link JwtDecoder} so the resource server starts
 * without reaching the authorization-server. The decoder is never invoked — the {@code jwt()} MockMvc
 * mutator injects a pre-authenticated token directly into the security context.
 */
@TestConfiguration(proxyBeanMethods = false)
public class IdentityTestConfig {

    @Bean
    @ServiceConnection
    PostgreSQLContainer<?> postgresContainer() {
        return new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                .withDatabaseName("aegis_identity");
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return token -> {
            throw new UnsupportedOperationException(
                    "JwtDecoder is not used in tests; the jwt() mutator injects authentication");
        };
    }
}
