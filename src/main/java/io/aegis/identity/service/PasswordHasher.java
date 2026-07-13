package io.aegis.identity.service;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Password hashing using Argon2id (memory-hard, the current best-practice for password storage).
 * Wraps Spring Security's {@link Argon2PasswordEncoder}, which requires Bouncy Castle on the
 * classpath. A legacy bcrypt import path with upgrade-on-login is a documented enhancement
 * (see ARCHITECTURE.md §6.1); this class is the single place credential hashing is defined.
 */
@Component
public class PasswordHasher {

    private final PasswordEncoder encoder;

    public PasswordHasher() {
        // Spring Security's recommended Argon2id parameters.
        this.encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    public String hash(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("password must not be blank");
        }
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String encodedHash) {
        if (rawPassword == null || encodedHash == null) {
            return false;
        }
        return encoder.matches(rawPassword, encodedHash);
    }
}
