package io.aegis.identity;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AuthPolicy;
import io.aegis.identity.service.AuthOutcome;
import io.aegis.identity.service.AuthPolicyService;
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
 * Self-service password change: {@code POST /api/v1/users/me/password}. A user changes their OWN
 * password (no admin scope), resolved from the token — never the body. Covers the auth boundary and
 * the current-password / policy checks.
 */
@SpringBootTest
@org.springframework.test.context.ActiveProfiles("dev") // dev profile: ddl-auto=update creates the schema; dev password fallback
@Import(IdentityTestConfig.class)
class ChangePasswordIT {

    @Autowired
    WebApplicationContext context;
    @Autowired
    UserService userService;
    @Autowired
    AuthPolicyService authPolicyService;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void no_token_is_unauthorized() throws Exception {
        String body = """
                {"currentPassword":"Sup3rSecret!","newPassword":"N3wPassword!"}""";
        mockMvc.perform(post("/api/v1/users/me/password")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void valid_current_password_and_compliant_new_password_returns_204_and_rotates_credential()
            throws Exception {
        AppUser user = userService.createUser("cpt-a", "alice", "alice@a.example", "Sup3rSecret!");
        String body = """
                {"currentPassword":"Sup3rSecret!","newPassword":"N3wStrongPass!"}""";

        // subject == the AppUser UUID (production token shape) resolves the caller to their own account.
        mockMvc.perform(post("/api/v1/users/me/password")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("cpt-a", user.getId().toString())))
                .andExpect(status().isNoContent());

        // The new password now authenticates; the old one no longer does.
        assertThat(userService.authenticate("cpt-a", "alice", "N3wStrongPass!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
        assertThat(userService.authenticate("cpt-a", "alice", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.BAD_CREDENTIALS);
    }

    @Test
    void resolves_caller_by_preferred_username_when_subject_is_not_a_uuid() throws Exception {
        userService.createUser("cpt-b", "bob", "bob@b.example", "Sup3rSecret!");
        String body = """
                {"currentPassword":"Sup3rSecret!","newPassword":"N3wStrongPass!"}""";

        // A non-UUID subject with a preferred_username claim resolves by username within the tenant.
        mockMvc.perform(post("/api/v1/users/me/password")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwt().jwt(j -> j.subject("bob")
                                .claim("tenant", "cpt-b")
                                .claim("preferred_username", "bob"))))
                .andExpect(status().isNoContent());

        assertThat(userService.authenticate("cpt-b", "bob", "N3wStrongPass!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
    }

    @Test
    void wrong_current_password_returns_400_and_does_not_change_the_credential() throws Exception {
        AppUser user = userService.createUser("cpt-c", "carol", "carol@c.example", "Sup3rSecret!");
        String body = """
                {"currentPassword":"wrong-password","newPassword":"N3wStrongPass!"}""";

        mockMvc.perform(post("/api/v1/users/me/password")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("cpt-c", user.getId().toString())))
                .andExpect(status().isBadRequest());

        // The original password still works — the change was rejected.
        assertThat(userService.authenticate("cpt-c", "carol", "Sup3rSecret!").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
    }

    @Test
    void policy_violating_new_password_returns_400() throws Exception {
        // Tighten this tenant's policy so a new password must contain a digit.
        AuthPolicy tighten = new AuthPolicy("cpt-d");
        tighten.setPasswordMinLength(8);
        tighten.setPasswordRequireDigit(true);
        authPolicyService.update("cpt-d", tighten);

        AppUser user = userService.createUser("cpt-d", "dave", "dave@d.example", "Sup3rSecret1");
        // 12 letters, no digit: passes DTO @Size(min=8) but violates the tenant password policy.
        String body = """
                {"currentPassword":"Sup3rSecret1","newPassword":"OnlyLettersHere"}""";

        mockMvc.perform(post("/api/v1/users/me/password")
                        .contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(jwtForTenant("cpt-d", user.getId().toString())))
                .andExpect(status().isBadRequest());

        // Original password still valid — the change was rejected by policy.
        assertThat(userService.authenticate("cpt-d", "dave", "Sup3rSecret1").outcome())
                .isEqualTo(AuthOutcome.SUCCESS);
    }
}
