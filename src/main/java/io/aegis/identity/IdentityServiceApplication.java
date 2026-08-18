package io.aegis.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Aegis Identity Service — the universal directory (users, credentials, groups), tenant-scoped. */
@SpringBootApplication
@org.springframework.scheduling.annotation.EnableScheduling // outbox relay
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
