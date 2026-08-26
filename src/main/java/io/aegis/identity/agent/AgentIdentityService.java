package io.aegis.identity.agent;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import io.aegis.identity.agent.AgentExceptions.AgentNotFoundException;
import io.aegis.identity.agent.AgentExceptions.AgentOwnerInvalidException;
import io.aegis.identity.agent.AgentExceptions.DuplicateAgentException;
import io.aegis.identity.domain.AppUserRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Agent lifecycle, with one rule doing most of the work: <b>accountability before autonomy</b>.
 *
 * <p>An agent cannot be registered without a real owner in the same tenant. That single constraint
 * is what keeps an agent estate governable — every agent traces to a party who can be notified when
 * it misbehaves and who can be asked whether it should still exist.
 */
@Service
public class AgentIdentityService {

    private static final String USER_PREFIX = "user:";
    private static final String SERVICE_PREFIX = "service:";

    private final AgentIdentityRepository agents;
    private final AppUserRepository users;
    private final AuditEventPublisher audit;

    public AgentIdentityService(AgentIdentityRepository agents, AppUserRepository users,
                                AuditEventPublisher audit) {
        this.agents = agents;
        this.users = users;
        this.audit = audit;
    }

    @Transactional
    public AgentIdentity register(String tenantId, String agentId, String displayName,
                                  String ownerPrincipal) {
        requireValidOwner(tenantId, ownerPrincipal);

        if (agents.existsByTenantIdAndAgentId(tenantId, agentId)) {
            throw new DuplicateAgentException("agent already registered in this tenant: " + agentId);
        }

        AgentIdentity agent = agents.save(new AgentIdentity(tenantId, agentId, displayName, ownerPrincipal));
        record(tenantId, "agent.registered", agentId, AuditOutcome.SUCCESS, ownerPrincipal);
        return agent;
    }

    /**
     * Validate the owner edge.
     *
     * <p>A {@code user:} owner must resolve to a real user <em>in this tenant</em> — the lookup is
     * tenant-scoped, so a genuine user of another tenant simply does not resolve, which is the
     * cross-tenant defence. A {@code service:} owner is accepted without a directory lookup because
     * workloads are not in the user directory, and requiring one would make it impossible for a
     * service to own an agent. Any other namespace is refused: an owner we cannot validate is
     * indistinguishable from no owner at all.
     */
    private void requireValidOwner(String tenantId, String ownerPrincipal) {
        if (ownerPrincipal == null || ownerPrincipal.isBlank()) {
            throw new AgentOwnerInvalidException(
                    "agent owner is required — an agent must have an accountable owner");
        }
        if (ownerPrincipal.startsWith(SERVICE_PREFIX)) {
            return;
        }
        if (!ownerPrincipal.startsWith(USER_PREFIX)) {
            throw new AgentOwnerInvalidException(
                    "unrecognised owner principal namespace: " + ownerPrincipal
                            + " (expected " + USER_PREFIX + " or " + SERVICE_PREFIX + ")");
        }
        String username = ownerPrincipal.substring(USER_PREFIX.length());
        users.findByTenantIdAndUsername(tenantId, username).orElseThrow(() ->
                new AgentOwnerInvalidException(
                        "agent owner does not exist in this tenant: " + ownerPrincipal));
    }

    @Transactional
    public void revoke(String tenantId, String agentId, String reason) {
        AgentIdentity agent = require(tenantId, agentId);
        agent.revoke(reason);
        agents.save(agent);
        record(tenantId, "agent.revoked", agentId, AuditOutcome.SUCCESS, agent.getOwnerPrincipal());
    }

    @Transactional
    public void activate(String tenantId, String agentId) {
        AgentIdentity agent = require(tenantId, agentId);
        agent.activate();
        agents.save(agent);
        record(tenantId, "agent.activated", agentId, AuditOutcome.SUCCESS, agent.getOwnerPrincipal());
    }

    @Transactional
    public void suspend(String tenantId, String agentId) {
        AgentIdentity agent = require(tenantId, agentId);
        agent.suspend();
        agents.save(agent);
        record(tenantId, "agent.suspended", agentId, AuditOutcome.SUCCESS, agent.getOwnerPrincipal());
    }

    /** Whether this agent currently exists and may act. An unknown agent may not. */
    @Transactional(readOnly = true)
    public boolean canAct(String tenantId, String agentId) {
        return agents.findByTenantIdAndAgentId(tenantId, agentId)
                .map(AgentIdentity::canAct)
                .orElse(false);
    }

    @Transactional(readOnly = true)
    public List<AgentIdentity> list(String tenantId) {
        return agents.findByTenantIdOrderByAgentId(tenantId);
    }

    /** Every agent a given owner is answerable for — the "what am I responsible for?" query. */
    @Transactional(readOnly = true)
    public List<AgentIdentity> ownedBy(String tenantId, String ownerPrincipal) {
        return agents.findByTenantIdAndOwnerPrincipal(tenantId, ownerPrincipal);
    }

    private AgentIdentity require(String tenantId, String agentId) {
        return agents.findByTenantIdAndAgentId(tenantId, agentId)
                .orElseThrow(() -> new AgentNotFoundException("unknown agent: " + agentId));
    }

    private void record(String tenantId, String action, String agentId, AuditOutcome outcome,
                        String owner) {
        if (audit == null) {
            return;
        }
        audit.publish(AuditEvent.of("agent", action, outcome)
                .tenant(tenantId)
                .target(agentId)
                .attribute("owner", owner)
                .build());
    }
}
