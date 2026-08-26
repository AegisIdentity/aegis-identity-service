package io.aegis.identity.agent;

/**
 * Typed agent-domain failures, so the API answers with a meaningful status instead of a 500.
 *
 * <p>Raw {@code IllegalArgumentException} reaching the dispatcher produces a 500 and a logged stack
 * trace — which tells a caller nothing actionable, and tells a would-be attacker that they found an
 * unhandled path. These mirror the existing {@code UserExceptions} house style.
 */
public final class AgentExceptions {

    private AgentExceptions() {
    }

    /** The owner edge is missing, malformed, or names a principal that does not exist here. */
    public static class AgentOwnerInvalidException extends RuntimeException {
        public AgentOwnerInvalidException(String message) {
            super(message);
        }
    }

    /** An agent with this id already exists in this tenant. */
    public static class DuplicateAgentException extends RuntimeException {
        public DuplicateAgentException(String message) {
            super(message);
        }
    }

    public static class AgentNotFoundException extends RuntimeException {
        public AgentNotFoundException(String message) {
            super(message);
        }
    }

    /** Revocation is terminal; a revoked agent cannot be brought back. */
    public static class AgentRevokedException extends RuntimeException {
        public AgentRevokedException(String message) {
            super(message);
        }
    }
}
