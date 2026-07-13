package io.aegis.identity.config;

import io.aegis.commons.security.CorsConfigFactory;
import io.aegis.commons.security.SecurityHardening;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Resource-server security for the identity API. Default-deny; each endpoint requires a specific
 * OAuth scope. Applies the shared hardening baseline (headers, stateless, 401-not-302) from
 * {@code aegis-security-commons}. Tokens are validated against the authorization-server issuer.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        SecurityHardening.applyHardeningHeaders(http);
        SecurityHardening.statelessBearerApi(http);
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // public onboarding — a brand-new organization has no token yet
                        .requestMatchers(HttpMethod.POST, "/api/v1/onboarding").permitAll()
                        // users
                        .requestMatchers(HttpMethod.POST, "/api/v1/users:authenticate")
                        .hasAuthority("SCOPE_identity:users:authenticate")
                        .requestMatchers(HttpMethod.POST, "/api/v1/users", "/api/v1/users/**")
                        .hasAuthority("SCOPE_identity:users:write")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/users/**")
                        .hasAuthority("SCOPE_identity:users:write")
                        .requestMatchers(HttpMethod.GET, "/api/v1/users", "/api/v1/users/**")
                        .hasAuthority("SCOPE_identity:users:read")
                        // groups (GET = read; all other methods = write)
                        .requestMatchers(HttpMethod.GET, "/api/v1/groups", "/api/v1/groups/**")
                        .hasAuthority("SCOPE_identity:groups:read")
                        .requestMatchers("/api/v1/groups", "/api/v1/groups/**")
                        .hasAuthority("SCOPE_identity:groups:write")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${aegis.cors.allowed-origins}") List<String> allowedOrigins) {
        return CorsConfigFactory.fromAllowedOrigins(allowedOrigins);
    }
}
