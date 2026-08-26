package io.aegis.identity.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.aegis.commons.agent.AgentStatus;
import io.aegis.commons.agent.AutonomyLevel;
import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.identity.domain.AppUser;
import io.aegis.identity.domain.AppUserRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * <b>Accountability before autonomy.</b> Every agent must name an owner — the human or service
 * answerable for what it does — and that owner must be real and must belong to the same tenant.
 * Without it, "the agent did it" is an unanswerable statement and there is nobody to escalate to,
 * notify, or revoke.
 */
class AgentIdentityServiceTest {

    private final AgentIdentityRepository agents = mock(AgentIdentityRepository.class);
    private final AppUserRepository users = mock(AppUserRepository.class);
    private final AuditEventPublisher audit = mock(AuditEventPublisher.class);
    private final AgentIdentityService service = new AgentIdentityService(agents, users, audit);

    private void ownerExists(String tenant, String username) {
        when(users.findByTenantIdAndUsername(tenant, username))
                .thenReturn(Optional.of(new AppUser(UUID.randomUUID(), tenant, username,
                        username + "@example.com", "{argon2}x")));
    }

    private void saveEchoes() {
        when(agents.save(any(AgentIdentity.class))).thenAnswer(i -> i.getArgument(0));
    }

    @Test
    void registers_an_agent_with_its_owner_edge() {
        ownerExists("acme", "alice");
        saveEchoes();

        AgentIdentity agent = service.register("acme", "agent:planner", "Planner", "user:alice");

        assertThat(agent.getTenantId()).isEqualTo("acme");
        assertThat(agent.getAgentId()).isEqualTo("agent:planner");
        assertThat(agent.getOwnerPrincipal()).isEqualTo("user:alice");
        assertThat(agent.getStatus()).isEqualTo(AgentStatus.ACTIVE);
    }

    @Test
    void a_new_agent_starts_at_the_most_restrictive_autonomy() {
        // Registration proves accountability, not trustworthiness. Autonomy is granted deliberately
        // afterwards, never as a side effect of being registered.
        ownerExists("acme", "alice");
        saveEchoes();

        assertThat(service.register("acme", "agent:planner", "Planner", "user:alice").getAutonomy())
                .isEqualTo(AutonomyLevel.CONFIRM_EACH);
    }

    @Test
    void refuses_an_agent_with_no_owner() {
        assertThatThrownBy(() -> service.register("acme", "agent:orphan", "Orphan", null))
                .isInstanceOf(AgentExceptions.AgentOwnerInvalidException.class);
        assertThatThrownBy(() -> service.register("acme", "agent:orphan", "Orphan", "  "))
                .isInstanceOf(AgentExceptions.AgentOwnerInvalidException.class);
    }

    @Test
    void refuses_an_owner_who_does_not_exist() {
        when(users.findByTenantIdAndUsername("acme", "ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.register("acme", "agent:x", "X", "user:ghost"))
                .isInstanceOf(AgentExceptions.AgentOwnerInvalidException.class)
                .hasMessageContaining("owner");
    }

    @Test
    void refuses_an_owner_from_another_tenant() {
        // The cross-tenant negative test this platform requires of every new surface. The owner
        // lookup is tenant-scoped, so a real user in globex simply does not resolve inside acme.
        when(users.findByTenantIdAndUsername("acme", "alice")).thenReturn(Optional.empty());
        ownerExists("globex", "alice");

        assertThatThrownBy(() -> service.register("acme", "agent:x", "X", "user:alice"))
                .isInstanceOf(AgentExceptions.AgentOwnerInvalidException.class);
    }

    @Test
    void accepts_a_service_principal_owner_without_a_directory_lookup() {
        // Service principals are not in the user directory, so requiring a lookup would make it
        // impossible to own an agent with a workload — which is a legitimate case.
        saveEchoes();

        AgentIdentity agent = service.register("acme", "agent:sync", "Sync", "service:scim");
        assertThat(agent.getOwnerPrincipal()).isEqualTo("service:scim");
    }

    @Test
    void refuses_an_owner_with_an_unknown_principal_namespace() {
        // Fail closed on a namespace we cannot validate, rather than trusting an arbitrary string.
        assertThatThrownBy(() -> service.register("acme", "agent:x", "X", "wat:alice"))
                .isInstanceOf(AgentExceptions.AgentOwnerInvalidException.class);
    }

    @Test
    void refuses_a_duplicate_agent_id_within_a_tenant() {
        ownerExists("acme", "alice");
        when(agents.existsByTenantIdAndAgentId("acme", "agent:planner")).thenReturn(true);

        assertThatThrownBy(() -> service.register("acme", "agent:planner", "Planner", "user:alice"))
                .isInstanceOf(AgentExceptions.DuplicateAgentException.class);
    }

    @Test
    void the_same_agent_id_may_exist_in_two_tenants() {
        ownerExists("globex", "bob");
        when(agents.existsByTenantIdAndAgentId("globex", "agent:planner")).thenReturn(false);
        saveEchoes();

        assertThat(service.register("globex", "agent:planner", "Planner", "user:bob").getTenantId())
                .isEqualTo("globex");
    }

    // --- lifecycle ------------------------------------------------------------------------------

    @Test
    void a_revoked_agent_may_not_act() {
        AgentIdentity agent = new AgentIdentity("acme", "agent:planner", "Planner", "user:alice");
        when(agents.findByTenantIdAndAgentId("acme", "agent:planner")).thenReturn(Optional.of(agent));
        saveEchoes();

        service.revoke("acme", "agent:planner", "compromised");

        assertThat(agent.getStatus()).isEqualTo(AgentStatus.REVOKED);
        assertThat(service.canAct("acme", "agent:planner")).isFalse();
    }

    @Test
    void revocation_is_terminal() {
        // A revoked agent is never reactivated — register a new one. Reactivation would silently
        // restore whatever consents and mandates the compromised identity still held.
        AgentIdentity agent = new AgentIdentity("acme", "agent:planner", "Planner", "user:alice");
        agent.revoke("compromised");
        when(agents.findByTenantIdAndAgentId("acme", "agent:planner")).thenReturn(Optional.of(agent));

        assertThatThrownBy(() -> service.activate("acme", "agent:planner"))
                .isInstanceOf(AgentExceptions.AgentRevokedException.class);
    }

    @Test
    void an_unknown_agent_may_not_act() {
        when(agents.findByTenantIdAndAgentId("acme", "agent:ghost")).thenReturn(Optional.empty());
        assertThat(service.canAct("acme", "agent:ghost")).isFalse();
    }

    @Test
    void registration_is_audited_with_the_owner_recorded() {
        ownerExists("acme", "alice");
        saveEchoes();

        service.register("acme", "agent:planner", "Planner", "user:alice");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).publish(captor.capture());
        AuditEvent event = captor.getValue();

        assertThat(event.type()).isEqualTo("agent");
        assertThat(event.action()).isEqualTo("agent.registered");
        assertThat(event.tenantId()).isEqualTo("acme");
        assertThat(event.target()).isEqualTo("agent:planner");
        assertThat(event.attributes()).containsEntry("owner", "user:alice");
    }

    @Test
    void maps_onto_the_shared_agent_principal_type() {
        AgentIdentity agent = new AgentIdentity("acme", "agent:planner", "Planner", "user:alice");
        var principal = agent.toAgentPrincipal();

        assertThat(principal.id()).isEqualTo("agent:planner");
        assertThat(principal.tenantId()).isEqualTo("acme");
        assertThat(principal.ownerPrincipal()).isEqualTo("user:alice");
    }
}
