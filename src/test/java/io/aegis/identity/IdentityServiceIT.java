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
@org.springframework.test.context.ActiveProfiles("dev") // dev profile: ddl-auto=update creates the schema; dev password fallback
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
    void authenticate_reports_the_tenants_mfa_requirement_so_the_as_can_step_up() throws Exception {
        // Default policy: MFA not required -> a successful authenticate returns mfaRequired=false.
        userService.createUser("mfaco", "gwen", "gwen@mfaco.example", "Sup3rSecret!");
        String body = """
                {"tenantId":"mfaco","username":"gwen","password":"Sup3rSecret!"}""";
        mockMvc.perform(post("/api/v1/users:authenticate")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("mfaco", "authz-server", "identity:users:authenticate")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("SUCCESS"))
                .andExpect(jsonPath("$.mfaRequired").value(false));

        // A tenant admin turns MFA on via the auth-policy endpoint.
        mockMvc.perform(put("/api/v1/auth-policy").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"passwordMinLength":8,"passwordRequireUppercase":false,
                                 "passwordRequireLowercase":false,"passwordRequireDigit":false,
                                 "passwordRequireSymbol":false,"lockoutThreshold":5,
                                 "lockoutDurationMinutes":15,"mfaRequired":true,"sessionTtlMinutes":60}""")
                        .with(jwtForTenant("mfaco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaRequired").value(true));

        // Now a successful authenticate for a user in that tenant reports mfaRequired=true.
        mockMvc.perform(post("/api/v1/users:authenticate")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("mfaco", "authz-server", "identity:users:authenticate")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("SUCCESS"))
                .andExpect(jsonPath("$.userId").isNotEmpty())
                .andExpect(jsonPath("$.mfaRequired").value(true));
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

        // public — no token needed for a brand-new org. Neutral 202 Accepted (M-core-2: no
        // existence oracle) echoing the caller's submitted values.
        mockMvc.perform(post("/api/v1/onboarding").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.tenant").value("acme"))
                .andExpect(jsonPath("$.adminUsername").value("admin"));

        // the new admin can now authenticate within that tenant
        assertThat(userService.authenticate("acme", "admin", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);

        // M-core-2: onboarding the same org again returns the SAME neutral 202 (not a 409), so an
        // unauthenticated caller cannot distinguish an existing org from a fresh one. The existing org
        // is silently NOT modified — the original admin still authenticates, the squatter's creds do not.
        mockMvc.perform(post("/api/v1/onboarding").contentType(MediaType.APPLICATION_JSON).content("""
                        {"organizationName":"Acme","tenantSlug":"acme","adminUsername":"other",
                         "adminEmail":"other@acme.example","adminPassword":"Sup3rSecret!"}"""))
                .andExpect(status().isAccepted());

        // the squatting attempt did not overwrite anything: the new creds do not work, the original do
        assertThat(userService.authenticate("acme", "other", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.BAD_CREDENTIALS);
        assertThat(userService.authenticate("acme", "admin", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
    }

    @Test
    void branding_is_public_to_read_and_tenant_admin_to_write() throws Exception {
        // public GET returns defaults (no token needed — the login page reads it pre-auth)
        mockMvc.perform(get("/api/v1/branding/brandco"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productName").value("Aegis Identity"));

        String body = """
                {"productName":"Acme SSO","signInHeading":"Welcome to Acme",
                 "signInSubtitle":"Sign in to continue","primaryColor":"#ff8800"}""";

        // write is scope-gated
        mockMvc.perform(put("/api/v1/branding").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(put("/api/v1/branding").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("brandco", "admin", "identity:users:read")))
                .andExpect(status().isForbidden());
        mockMvc.perform(put("/api/v1/branding").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("brandco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.productName").value("Acme SSO"))
                .andExpect(jsonPath("$.primaryColor").value("#ff8800"));

        // public GET now reflects the tenant's branding
        mockMvc.perform(get("/api/v1/branding/brandco"))
                .andExpect(jsonPath("$.signInHeading").value("Welcome to Acme"));

        // an invalid color is rejected
        mockMvc.perform(put("/api/v1/branding").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"productName":"X","signInHeading":"H","signInSubtitle":"S","primaryColor":"red"}""")
                        .with(jwtForTenant("brandco", "admin", "tenant:admin")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void auth_policy_is_scope_gated_and_password_rules_are_enforced() throws Exception {
        // scope-gated: no token -> 401, wrong scope -> 403, defaults returned with tenant:admin
        mockMvc.perform(get("/api/v1/auth-policy")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/auth-policy").with(jwtForTenant("polco", "admin", "identity:users:read")))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/v1/auth-policy").with(jwtForTenant("polco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passwordMinLength").value(8));

        // tighten: min length 12 + require a digit
        mockMvc.perform(put("/api/v1/auth-policy").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"passwordMinLength":12,"passwordRequireUppercase":false,
                                 "passwordRequireLowercase":false,"passwordRequireDigit":true,
                                 "passwordRequireSymbol":false,"lockoutThreshold":5,
                                 "lockoutDurationMinutes":15,"mfaRequired":false,"sessionTtlMinutes":60}""")
                        .with(jwtForTenant("polco", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passwordRequireDigit").value(true));

        // a weak password (no digit, too short) is now rejected on user creation
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"weak","email":"weak@polco.example","password":"onlyletters"}""")
                        .with(jwtForTenant("polco", "admin", "identity:users:write")))
                .andExpect(status().isBadRequest());

        // a compliant password succeeds
        mockMvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"strong","email":"strong@polco.example","password":"Str0ngPassw0rd"}""")
                        .with(jwtForTenant("polco", "admin", "identity:users:write")))
                .andExpect(status().isCreated());
    }

    @Test
    void federated_provisioning_is_find_or_create_by_email_and_scope_gated() throws Exception {
        String body = """
                {"tenantId":"fed","email":"jane@fed.example","username":"jane"}""";

        // no token -> 401; wrong scope -> 403
        mockMvc.perform(post("/api/v1/users:provision").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/users:provision").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("fed", "as", "identity:users:read")))
                .andExpect(status().isForbidden());

        // provision scope -> creates the user
        String first = mockMvc.perform(post("/api/v1/users:provision")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("fed", "as", "identity:users:provision")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("jane@fed.example"))
                .andReturn().getResponse().getContentAsString();
        String id = com.jayway.jsonpath.JsonPath.read(first, "$.id");

        // calling again with the same email returns the SAME user (idempotent, no duplicate)
        mockMvc.perform(post("/api/v1/users:provision").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"tenantId":"fed","email":"jane@fed.example","username":"different"}""")
                        .with(jwtForTenant("fed", "as", "identity:users:provision")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id));
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
