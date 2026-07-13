package io.aegis.identity;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.service.AuthOutcome;
import io.aegis.identity.service.UserExceptions.UserNotFoundException;
import io.aegis.identity.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Integration tests for identity-service against real Postgres. Covers the security-critical
 * behaviours: tenant isolation, Argon2 verification, lockout, and scope-based authorization.
 */
@SpringBootTest
@Import(IdentityTestConfig.class)
class IdentityServiceIT {

    @Autowired
    WebApplicationContext context;
    @Autowired
    UserService userService;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    // ---- Service-level: tenant isolation + credential verification + lockout ----

    @Test
    void a_user_in_one_tenant_is_invisible_to_another_tenant() {
        AppUser created = userService.createUser("tenant-a", "alice", "alice@a.example", "Sup3rSecret!");
        // Same id, different tenant -> not found (cross-tenant read is denied by construction).
        assertThatThrownBy(() -> userService.getUser("tenant-b", created.getId()))
                .isInstanceOf(UserNotFoundException.class);
        // Correct tenant -> found.
        assertThat(userService.getUser("tenant-a", created.getId()).getUsername()).isEqualTo("alice");
    }

    @Test
    void authenticate_succeeds_with_correct_password_and_fails_with_wrong() {
        userService.createUser("tenant-a", "bob", "bob@a.example", "Sup3rSecret!");
        assertThat(userService.authenticate("tenant-a", "bob", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
        assertThat(userService.authenticate("tenant-a", "bob", "nope").outcome())
                .isEqualTo(AuthOutcome.BAD_CREDENTIALS);
    }

    @Test
    void unknown_username_returns_bad_credentials_not_a_distinct_error() {
        assertThat(userService.authenticate("tenant-a", "ghost", "whatever").outcome())
                .isEqualTo(AuthOutcome.BAD_CREDENTIALS);
    }

    @Test
    void account_locks_after_five_consecutive_failures() {
        userService.createUser("tenant-a", "carol", "carol@a.example", "Sup3rSecret!");
        for (int i = 0; i < 4; i++) {
            assertThat(userService.authenticate("tenant-a", "carol", "wrong").outcome())
                    .isEqualTo(AuthOutcome.BAD_CREDENTIALS);
        }
        // 5th failure trips the lock.
        assertThat(userService.authenticate("tenant-a", "carol", "wrong").outcome())
                .isEqualTo(AuthOutcome.LOCKED);
        // Even the correct password is now refused while locked.
        assertThat(userService.authenticate("tenant-a", "carol", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.LOCKED);
    }

    // ---- HTTP-level: scope-based authorization ----

    @Test
    void create_user_requires_write_scope() throws Exception {
        String body = """
                {"username":"dave","email":"dave@a.example","password":"Sup3rSecret!"}""";

        // No token -> 401.
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());

        // Read scope only -> 403.
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:read")))
                .andExpect(status().isForbidden());

        // Write scope -> 201.
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:write")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("dave"))
                .andExpect(jsonPath("$.tenantId").value("tenant-a"));
    }

    @Test
    void authenticate_endpoint_requires_authenticate_scope_and_verifies() throws Exception {
        userService.createUser("tenant-a", "erin", "erin@a.example", "Sup3rSecret!");
        String body = """
                {"tenantId":"tenant-a","username":"erin","password":"Sup3rSecret!"}""";

        mockMvc.perform(post("/api/v1/users:authenticate")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("tenant-a", "authz-server", "identity:users:authenticate")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("SUCCESS"));
    }

    @Test
    void users_can_be_listed_disabled_enabled_and_deleted() throws Exception {
        var user = userService.createUser("tenant-a", "frank", "frank@a.example", "Sup3rSecret!");

        mockMvc.perform(get("/api/v1/users").with(jwtForTenant("tenant-a", "svc", "identity:users:read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.username=='frank')]").exists());

        mockMvc.perform(post("/api/v1/users/" + user.getId() + "/disable")
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:write")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("DISABLED"));

        mockMvc.perform(post("/api/v1/users/" + user.getId() + "/enable")
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:write")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ACTIVE"));

        mockMvc.perform(delete("/api/v1/users/" + user.getId())
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:write")))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/v1/users/" + user.getId())
                        .with(jwtForTenant("tenant-a", "svc", "identity:users:read")))
                .andExpect(status().isNotFound());
    }

    @Test
    void groups_crud_and_membership_with_scope_enforcement() throws Exception {
        var user = userService.createUser("tenant-a", "grace", "grace@a.example", "Sup3rSecret!");

        // read scope cannot create a group
        mockMvc.perform(post("/api/v1/groups").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"X\"}")
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:read")))
                .andExpect(status().isForbidden());

        // create with write scope
        var created = mockMvc.perform(post("/api/v1/groups").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Engineers\",\"description\":\"Eng team\"}")
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:write")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Engineers"))
                .andReturn();
        String groupId = com.jayway.jsonpath.JsonPath.read(
                created.getResponse().getContentAsString(), "$.id");

        // add + list member
        mockMvc.perform(post("/api/v1/groups/" + groupId + "/members")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":\"" + user.getId() + "\"}")
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:write")))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/v1/groups/" + groupId + "/members")
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("grace"));
        mockMvc.perform(get("/api/v1/groups/" + groupId)
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:read")))
                .andExpect(jsonPath("$.memberCount").value(1));

        // remove member
        mockMvc.perform(delete("/api/v1/groups/" + groupId + "/members/" + user.getId())
                        .with(jwtForTenant("tenant-a", "svc", "identity:groups:write")))
                .andExpect(status().isNoContent());

        // unauthenticated is denied
        mockMvc.perform(get("/api/v1/groups")).andExpect(status().isUnauthorized());
    }

    @Test
    void onboarding_bootstraps_a_new_orgs_first_admin_and_is_idempotent() throws Exception {
        String body = """
                {"organizationName":"Acme Inc","tenantSlug":"acme","adminUsername":"admin",
                 "adminEmail":"admin@acme.example","adminPassword":"Sup3rSecret!"}""";

        // public — no token needed for a brand-new org
        mockMvc.perform(post("/api/v1/onboarding").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tenant").value("acme"))
                .andExpect(jsonPath("$.adminUsername").value("admin"));

        // the new admin can now authenticate within that tenant
        assertThat(userService.authenticate("acme", "admin", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);

        // onboarding the same org again is rejected (it already has users)
        mockMvc.perform(post("/api/v1/onboarding").contentType(MediaType.APPLICATION_JSON).content("""
                        {"organizationName":"Acme","tenantSlug":"acme","adminUsername":"other",
                         "adminEmail":"other@acme.example","adminPassword":"Sup3rSecret!"}"""))
                .andExpect(status().isConflict());
    }

    @Test
    void self_service_signup_is_closed_by_default_and_opens_after_admin_opts_in() throws Exception {
        String signup = """
                {"tenantSlug":"signupco","username":"cust1","email":"cust1@x.example","password":"Sup3rSecret!"}""";

        // Closed by default: the tenant has not opted in, so public sign-up is refused.
        mockMvc.perform(post("/api/v1/signup").contentType(MediaType.APPLICATION_JSON).content(signup))
                .andExpect(status().isForbidden());

        // The policy endpoint is scope-gated: no token -> 401, wrong scope -> 403.
        mockMvc.perform(get("/api/v1/signup-policy")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/signup-policy")
                        .with(jwtForTenant("signupco", "admin", "identity:users:read")))
                .andExpect(status().isForbidden());

        // The tenant admin opts in (tenant taken from the token, not the request).
        mockMvc.perform(put("/api/v1/signup-policy").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true}")
                        .with(jwtForTenant("signupco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant").value("signupco"))
                .andExpect(jsonPath("$.signupEnabled").value(true));

        // Now a customer can self-register, and then authenticate.
        mockMvc.perform(post("/api/v1/signup").contentType(MediaType.APPLICATION_JSON).content(signup))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tenant").value("signupco"))
                .andExpect(jsonPath("$.username").value("cust1"));
        assertThat(userService.authenticate("signupco", "cust1", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
    }

    @Test
    void signup_does_not_reveal_whether_an_org_exists_and_is_per_tenant() throws Exception {
        // "otherco" exists (has a user) but has NOT opted in; "ghostco" does not exist at all.
        userService.createUser("otherco", "someone", "someone@x.example", "Sup3rSecret!");
        String existingButClosed = """
                {"tenantSlug":"otherco","username":"x","email":"x@x.example","password":"Sup3rSecret!"}""";
        String unknownOrg = """
                {"tenantSlug":"ghostco","username":"x","email":"x@x.example","password":"Sup3rSecret!"}""";

        // Both indistinguishable (403): a closed tenant and a non-existent one look the same.
        mockMvc.perform(post("/api/v1/signup").contentType(MediaType.APPLICATION_JSON).content(existingButClosed))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/signup").contentType(MediaType.APPLICATION_JSON).content(unknownOrg))
                .andExpect(status().isForbidden());

        // An admin enabling sign-up for their own tenant does not open it for another tenant.
        mockMvc.perform(put("/api/v1/signup-policy").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true}")
                        .with(jwtForTenant("enabledco", "admin", "tenant:admin")))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/signup").contentType(MediaType.APPLICATION_JSON).content(existingButClosed))
                .andExpect(status().isForbidden());
    }
}
