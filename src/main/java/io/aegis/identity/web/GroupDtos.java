package io.aegis.identity.web;

import io.aegis.identity.domain.UserGroup;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public final class GroupDtos {

    private GroupDtos() {
    }

    public record CreateGroupRequest(
            @NotBlank @Size(max = 128) String name,
            @Size(max = 512) String description) {
    }

    public record GroupResponse(UUID id, String name, String description, long memberCount) {
        public static GroupResponse from(UserGroup g, long memberCount) {
            return new GroupResponse(g.getId(), g.getName(), g.getDescription(), memberCount);
        }
    }

    public record AddMemberRequest(@NotNull UUID userId) {
    }
}
