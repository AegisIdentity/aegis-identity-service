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
}
