package io.aegis.identity;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.aegis.identity.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * System-log (audit) read API: {@code GET /api/v1/system-log}. Gated by {@code SCOPE_tenant:admin} and
 * tenant-scoped from the token — an admin only ever sees their own organization's events.
 */
@SpringBootTest
@Import(IdentityTestConfig.class)
class SystemLogIT {

    @Autowired
    WebApplicationContext context;
    @Autowired
    UserService userService;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void no_token_is_unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/system-log")).andExpect(status().isUnauthorized());
    }

    @Test
    void wrong_scope_is_forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/system-log")
                        .with(jwtForTenant("slog-a", "admin", "identity:users:read")))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_sees_own_tenant_events_and_not_another_tenants() throws Exception {
        // Creating a user in tenant A emits a USER_CREATED audit event for tenant A.
        userService.createUser("slog-a", "alice", "alice@a.example", "Sup3rSecret!");
        // Tenant B has no events.

        mockMvc.perform(get("/api/v1/system-log")
                        .with(jwtForTenant("slog-a", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.action=='USER_CREATED' && @.target=='alice')]").exists())
                .andExpect(jsonPath("$[0].tenantId").value("slog-a"));

        // Tenant B admin sees nothing from tenant A (no cross-tenant reads).
        mockMvc.perform(get("/api/v1/system-log")
                        .with(jwtForTenant("slog-b", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.target=='alice')]").doesNotExist())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void events_are_newest_first_and_respect_the_limit() throws Exception {
        userService.createUser("slog-c", "u1", "u1@c.example", "Sup3rSecret!");
        Thread.sleep(10); // guarantee a distinct createdAt so ordering is deterministic
        userService.createUser("slog-c", "u2", "u2@c.example", "Sup3rSecret!");

        // limit=1 returns only the single newest event (u2 was created last).
        mockMvc.perform(get("/api/v1/system-log").param("limit", "1")
                        .with(jwtForTenant("slog-c", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].target").value("u2"));
    }
}
