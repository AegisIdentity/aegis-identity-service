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
                        // public self-service sign-up — a tenant's customer with no token; the service
                        // itself gates this on the tenant having opted in (default: closed)
                        .requestMatchers(HttpMethod.POST, "/api/v1/signup").permitAll()
                        // tenant admin reads their own branding (tenant from token)
                        .requestMatchers(HttpMethod.GET, "/api/v1/branding")
                        .hasAuthority("SCOPE_tenant:admin")
                        // public branding read by tenant — the login page renders it before authentication
                        .requestMatchers(HttpMethod.GET, "/api/v1/branding/**").permitAll()
                        // tenant admin sets their own branding
                        .requestMatchers(HttpMethod.PUT, "/api/v1/branding")
                        .hasAuthority("SCOPE_tenant:admin")
                        // tenant admin toggles/reads their own self-service sign-up policy
                        .requestMatchers("/api/v1/signup-policy")
                        .hasAuthority("SCOPE_tenant:admin")
                        // tenant admin reads/updates their own authentication policy
                        .requestMatchers("/api/v1/auth-policy")
                        .hasAuthority("SCOPE_tenant:admin")
                        // tenant admin reads their own system log (audit events; tenant from token)
                        .requestMatchers(HttpMethod.GET, "/api/v1/system-log")
                        .hasAuthority("SCOPE_tenant:admin")
                        // self-service password change — a user changes their OWN password; must come
                        // BEFORE the broad /api/v1/users/** write rule so it isn't captured by it
                        .requestMatchers(HttpMethod.POST, "/api/v1/users/me/password")
                        .authenticated()
                        // users
                        .requestMatchers(HttpMethod.POST, "/api/v1/users:authenticate")
                        .hasAuthority("SCOPE_identity:users:authenticate")
                        // JIT provisioning for federated logins (authorization-server service token)
                        .requestMatchers(HttpMethod.POST, "/api/v1/users:provision")
                        .hasAuthority("SCOPE_identity:users:provision")
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

    /**
     * CORS origins. {@code CorsConfigFactory} requires https:// origins, with a dev-only escape
     * hatch for plaintext localhost — and that escape hatch must actually be passed, or the service
     * fails to START under the local stack, which serves the console over http://localhost.
     * Gating it on the explicit {@code dev} profile keeps the production rule fail-closed: a
     * stage/prod deploy that is handed an http:// origin still refuses to start rather than
     * silently allowing a plaintext origin to read authenticated responses.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${aegis.cors.allowed-origins}") List<String> allowedOrigins,
            org.springframework.core.env.Environment environment) {
        boolean devProfile = java.util.Arrays.stream(environment.getActiveProfiles())
                .anyMatch(profile -> profile.equalsIgnoreCase("dev"));
        return CorsConfigFactory.fromAllowedOrigins(allowedOrigins, devProfile);
    }
}
