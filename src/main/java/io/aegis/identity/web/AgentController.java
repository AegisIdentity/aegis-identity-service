package io.aegis.identity.web;

import io.aegis.identity.agent.AgentIdentity;
import io.aegis.identity.agent.AgentIdentityService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Agent principal API. Tenant always comes from the token's {@code tenant} claim — never from the
 * request body or a path variable — so a caller cannot register an agent into another tenant.
 */
@RestController
public class AgentController {

    private final AgentIdentityService agents;

    public AgentController(AgentIdentityService agents) {
        this.agents = agents;
    }

    public record RegisterAgentRequest(
            @NotBlank String agentId,
            @NotBlank String displayName,
            /** The accountable human ({@code user:alice}) or workload ({@code service:scim}). */
            @NotBlank String ownerPrincipal) {
    }

    public record RevokeAgentRequest(String reason) {
    }

    public record AgentResponse(String agentId, String displayName, String ownerPrincipal,
                                String status, String autonomy, int maxDelegationDepth,
                                Instant createdAt, Instant revokedAt) {

        static AgentResponse from(AgentIdentity agent) {
            return new AgentResponse(agent.getAgentId(), agent.getDisplayName(),
                    agent.getOwnerPrincipal(), agent.getStatus().name(), agent.getAutonomy().name(),
                    agent.getMaxDelegationDepth(), agent.getCreatedAt(), agent.getRevokedAt());
        }
    }

    @GetMapping("/api/v1/agents")
    public List<AgentResponse> list(@AuthenticationPrincipal Jwt jwt,
                                    @RequestParam(required = false) String owner) {
        String tenant = tenantOf(jwt);
        List<AgentIdentity> found = owner == null || owner.isBlank()
                ? agents.list(tenant)
                : agents.ownedBy(tenant, owner);
        return found.stream().map(AgentResponse::from).toList();
    }

    @PostMapping("/api/v1/agents")
    public ResponseEntity<AgentResponse> register(@AuthenticationPrincipal Jwt jwt,
                                                  @Valid @RequestBody RegisterAgentRequest request) {
        AgentIdentity agent = agents.register(tenantOf(jwt), request.agentId(),
                request.displayName(), request.ownerPrincipal());
        return ResponseEntity.created(URI.create("/api/v1/agents/" + agent.getAgentId()))
                .body(AgentResponse.from(agent));
    }

    @PostMapping("/api/v1/agents/{agentId}:revoke")
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal Jwt jwt,
                                       @PathVariable String agentId,
                                       @RequestBody(required = false) RevokeAgentRequest request) {
        agents.revoke(tenantOf(jwt), agentId, request == null ? null : request.reason());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/agents/{agentId}:suspend")
    public ResponseEntity<Void> suspend(@AuthenticationPrincipal Jwt jwt, @PathVariable String agentId) {
        agents.suspend(tenantOf(jwt), agentId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/agents/{agentId}:activate")
    public ResponseEntity<Void> activate(@AuthenticationPrincipal Jwt jwt, @PathVariable String agentId) {
        agents.activate(tenantOf(jwt), agentId);
        return ResponseEntity.noContent().build();
    }

    private static String tenantOf(Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("token is missing the required 'tenant' claim");
        }
        return tenant;
    }
}
