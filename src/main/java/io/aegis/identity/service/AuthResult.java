package io.aegis.identity.service;

import java.util.UUID;

/** Outcome of {@code UserService.authenticate}; {@code userId} is present only on SUCCESS. */
public record AuthResult(AuthOutcome outcome, UUID userId) {

    public static AuthResult success(UUID userId) {
        return new AuthResult(AuthOutcome.SUCCESS, userId);
    }

    public static AuthResult of(AuthOutcome outcome) {
        return new AuthResult(outcome, null);
    }
}
