package io.aegis.identity.config;

import io.aegis.identity.domain.AppUserRepository;
import io.aegis.identity.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Seeds a default organization admin so the platform is usable out of the box:
 * <strong>Organization {@code dev} · Username {@code dev-user} · Password {@code dev-only-change-me}</strong>.
 * Idempotent, and disabled in production via {@code aegis.identity.seed-dev-admin=false}.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aegis.identity.seed-dev-admin", havingValue = "true", matchIfMissing = true)
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
