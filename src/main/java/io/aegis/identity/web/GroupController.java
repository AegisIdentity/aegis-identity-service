package io.aegis.identity.web;

import io.aegis.identity.domain.UserGroup;
import io.aegis.identity.service.GroupService;
import io.aegis.identity.web.GroupDtos.AddMemberRequest;
import io.aegis.identity.web.GroupDtos.CreateGroupRequest;
import io.aegis.identity.web.GroupDtos.GroupResponse;
import io.aegis.identity.web.UserDtos.UserResponse;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Group + membership API. Authorization by scope in {@code SecurityConfig}; tenant from the token. */
@RestController
public class GroupController {

    private final GroupService groupService;

    public GroupController(GroupService groupService) {
        this.groupService = groupService;
    }

    @GetMapping("/api/v1/groups")
    public List<GroupResponse> list(@AuthenticationPrincipal Jwt jwt) {
        return groupService.list(tenantOf(jwt)).stream()
                .map(g -> GroupResponse.from(g, groupService.memberCount(g.getId())))
                .toList();
    }

    @PostMapping("/api/v1/groups")
    public ResponseEntity<GroupResponse> create(@AuthenticationPrincipal Jwt jwt,
                                                @Valid @RequestBody CreateGroupRequest request) {
        UserGroup group = groupService.create(tenantOf(jwt), request.name(), request.description());
        return ResponseEntity.created(URI.create("/api/v1/groups/" + group.getId()))
                .body(GroupResponse.from(group, 0));
    }

    @GetMapping("/api/v1/groups/{id}")
    public GroupResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        UserGroup group = groupService.get(tenantOf(jwt), id);
        return GroupResponse.from(group, groupService.memberCount(id));
    }

    @DeleteMapping("/api/v1/groups/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        groupService.delete(tenantOf(jwt), id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/v1/groups/{id}/members")
    public List<UserResponse> members(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        return groupService.listMembers(tenantOf(jwt), id).stream().map(UserResponse::from).toList();
    }

    @PostMapping("/api/v1/groups/{id}/members")
    public ResponseEntity<Void> addMember(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                                          @Valid @RequestBody AddMemberRequest request) {
        groupService.addMember(tenantOf(jwt), id, request.userId());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/api/v1/groups/{id}/members/{userId}")
    public ResponseEntity<Void> removeMember(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                                             @PathVariable UUID userId) {
        groupService.removeMember(tenantOf(jwt), id, userId);
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
