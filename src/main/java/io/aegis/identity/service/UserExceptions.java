package io.aegis.identity.service;

/** Domain exceptions for the identity service. */
public final class UserExceptions {

    private UserExceptions() {
    }

    /** A username or email already exists within the tenant. */
    public static class DuplicateUserException extends RuntimeException {
        public DuplicateUserException(String message) {
            super(message);
        }
    }

    /** No such user in the tenant. */
    public static class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    /**
     * Self-service sign-up is not available for the requested organization — either it does not exist
     * or it has not enabled self-registration. Deliberately indistinguishable to avoid revealing which
     * organizations exist (enumeration).
     */
    public static class SignupNotAvailableException extends RuntimeException {
        public SignupNotAvailableException(String message) {
            super(message);
        }
    }

    /** A chosen password does not satisfy the tenant's password policy. */
    public static class PasswordPolicyException extends RuntimeException {
        public PasswordPolicyException(String message) {
            super(message);
        }
    }
}
