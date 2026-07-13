package io.aegis.identity.service;

/** Result of a credential verification attempt. Deliberately does not distinguish "no such user"
 * from "wrong password" to callers, to avoid username enumeration. */
public enum AuthOutcome {
    SUCCESS,
    BAD_CREDENTIALS,
    LOCKED,
    DISABLED
}
