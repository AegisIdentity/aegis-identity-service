package io.aegis.identity.outbox;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.identity.IdentityTestConfig;
import io.aegis.identity.service.UserService;
import java.time.Duration;
import java.util.Collections;
import java.util.Properties;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.kafka.ConfluentKafkaContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The transactional outbox, end to end: creating a user stages an {@code identity.user.created} event
 * in the same transaction, and the relay delivers it to Kafka — so the event survives the dual-write
 * gap between the DB commit and the publish. This is the reliability guarantee a best-effort publish
 * could not give the flagship lifecycle flow.
 */
@SpringBootTest(properties = {"aegis.outbox.poll-interval-ms=300"})
@org.springframework.test.context.ActiveProfiles("dev")
@Import(IdentityTestConfig.class)
class OutboxIT {

    @SuppressWarnings("resource")
    private static final ConfluentKafkaContainer KAFKA =
            new ConfluentKafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.8.0"));

    static {
        KAFKA.start();
    }

    @DynamicPropertySource
    static void kafka(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);
    }

    @Autowired
    UserService userService;

    @Autowired
    OutboxEventRepository outbox;

    @Test
    void creating_a_user_stages_and_relays_an_identity_user_created_event() {
        String username = "alice-" + java.util.UUID.randomUUID().toString().substring(0, 8);

        userService.createUser("dev", username, username + "@acme.test", "Sup3r-Secret-Pass!");

        // The event is delivered to the identity.user topic by the relay.
        try (KafkaConsumer<String, String> consumer = consumer()) {
            consumer.subscribe(Collections.singletonList("aegis.identity.user"));
            String found = pollFor(consumer, username);
            assertThat(found)
                    .contains("\"eventType\":\"identity.user.created\"")
                    .contains("\"tenantId\":\"dev\"")
                    .contains("\"username\":\"" + username + "\"");
        }

        // And the outbox row is marked published — the relay advanced it, not just staged it.
        Awaitility.await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(outbox.findByPublishedFalseOrderByCreatedAtAsc(
                        org.springframework.data.domain.Limit.of(100)))
                        .noneMatch(e -> e.getPayload().contains(username)));
    }

    private KafkaConsumer<String, String> consumer() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "outbox-it-" + java.util.UUID.randomUUID());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        return new KafkaConsumer<>(props);
    }

    private String pollFor(KafkaConsumer<String, String> consumer, String needle) {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
            for (ConsumerRecord<String, String> record : records) {
                if (record.value().contains(needle)) {
                    return record.value();
                }
            }
        }
        throw new AssertionError("no identity.user.created event for " + needle + " within timeout");
    }
}
