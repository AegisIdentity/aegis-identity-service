package io.aegis.identity;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * identity-service must START with the plaintext CORS origins the local stack injects. Companion to
 * tenant-service's CorsStartupIT — both services were patched for F1, so both are pinned. See that
 * class for why a factory-level unit test does not cover this.
 */
@SpringBootTest(properties = "aegis.cors.allowed-origins=http://localhost:3000,http://localhost:8080")
@ActiveProfiles("dev")
@Import(IdentityTestConfig.class)
class CorsStartupIT {

    @Test
    void the_context_starts_with_the_local_stack_plaintext_origins() {
    }
}
