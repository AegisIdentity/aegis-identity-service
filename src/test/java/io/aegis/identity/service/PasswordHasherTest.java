package io.aegis.identity.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PasswordHasherTest {

    private final PasswordHasher hasher = new PasswordHasher();

    @Test
    void hash_is_not_the_plaintext_and_is_argon2() {
        String hash = hasher.hash("Sup3rSecret!");
        assertThat(hash).isNotEqualTo("Sup3rSecret!").startsWith("$argon2");
    }

    @Test
    void correct_password_matches() {
        String hash = hasher.hash("Sup3rSecret!");
        assertThat(hasher.matches("Sup3rSecret!", hash)).isTrue();
    }

    @Test
    void wrong_password_does_not_match() {
        String hash = hasher.hash("Sup3rSecret!");
        assertThat(hasher.matches("wrong", hash)).isFalse();
    }

    @Test
    void same_password_hashes_differently_each_time_salted() {
        assertThat(hasher.hash("Sup3rSecret!")).isNotEqualTo(hasher.hash("Sup3rSecret!"));
    }

    @Test
    void blank_password_is_rejected() {
        assertThatThrownBy(() -> hasher.hash(" ")).isInstanceOf(IllegalArgumentException.class);
    }
}
