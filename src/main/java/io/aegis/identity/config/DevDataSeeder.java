package io.aegis.identity.config;

import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Seeds a default organization admin so the platform is usable out of the box:
 * <strong>Organization {@code dev} · Username {@code dev-user} · Password {@code dev-only-change-me}</strong>.
 * Idempotent.
 *
 * <p><b>Security (H2):</b> this seeder is fail-<em>closed</em>. It runs only when BOTH the {@code dev}
 * profile is active AND {@code aegis.identity.seed-dev-admin=true} is explicitly set ({@code
 * matchIfMissing = false} — opt-in, not opt-out). A stage/prod deploy that forgets a flag therefore
 * gets NO seeded account with a known password. The dev profile supplies the opt-in in application-dev.yml.
 */
@Configuration(proxyBeanMethods = false)
@Profile("dev")
@ConditionalOnProperty(name = "aegis.identity.seed-dev-admin", havingValue = "true", matchIfMissing = false)
public class DevDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);

    @Bean
    public ApplicationRunner seedDevAdmin(UserService userService, AppUserRepository users) {
        return args -> {
            if (!users.existsByTenantIdAndUsername("dev", "dev-user")) {
                userService.createUser("dev", "dev-user", "dev-user@aegis.local", "dev-only-change-me");
                log.info("Seeded dev admin — Organization=dev, Username=dev-user");
            }
        };
    }
}
