package io.aegis.identity.outbox;

import java.util.List;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.Limit;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Relays staged outbox events to Kafka. Runs on a short fixed schedule: it reads a bounded batch of
 * unpublished rows oldest-first, publishes each to its topic, and marks it published — all in one
 * transaction so a batch either fully advances or is retried.
 *
 * <p><b>At-least-once by construction.</b> If the process dies after a Kafka send but before the
 * transaction commits the {@code published} flag, the same rows are re-read and re-published on the
 * next run — so an event is never lost, but may be delivered more than once, which is why consumers
 * must be idempotent. Publishing <em>synchronously</em> (blocking on the send result) before marking
 * published is deliberate: it prevents marking a row published that never actually reached the broker.
 *
 * <p>Active only when Kafka is configured ({@code spring.kafka.bootstrap-servers}); otherwise the
 * outbox simply accumulates rows (and the service still works — see the correctness note in the
 * event README: identity.user.* consumers are best served by the outbox, but the events are not on a
 * request's critical path).
 */
@Component
@ConditionalOnProperty(name = "spring.kafka.bootstrap-servers")
public class OutboxRelay {

    private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);
    private static final int BATCH = 200;

    private final OutboxEventRepository outbox;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final long sendTimeoutMs;

    public OutboxRelay(OutboxEventRepository outbox, KafkaTemplate<String, String> kafkaTemplate,
                       @Value("${aegis.outbox.send-timeout-ms:5000}") long sendTimeoutMs) {
        this.outbox = outbox;
        this.kafkaTemplate = kafkaTemplate;
        this.sendTimeoutMs = sendTimeoutMs;
    }

    @Scheduled(fixedDelayString = "${aegis.outbox.poll-interval-ms:1000}")
    @Transactional
    public void relay() {
        List<OutboxEvent> pending = outbox.findByPublishedFalseOrderByCreatedAtAsc(Limit.of(BATCH));
        if (pending.isEmpty()) {
            return;
        }
        int published = 0;
        for (OutboxEvent event : pending) {
            try {
                // Block on the send so we only mark published what actually reached the broker.
                kafkaTemplate.send(event.getTopic(), event.getMessageKey(), event.getPayload())
                        .get(sendTimeoutMs, TimeUnit.MILLISECONDS);
                event.markPublished();
                published++;
            } catch (Exception e) {
                // Stop this batch — leave this and the rest unpublished so ordering is preserved and
                // they are retried next tick. Do not mark published on failure.
                log.warn("outbox relay halted at event {} ({}): {} — retrying next tick",
                        event.getId(), event.getEventType(), e.toString());
                break;
            }
        }
        if (published > 0) {
            outbox.saveAll(pending.subList(0, published));
            log.debug("outbox relay published {} event(s)", published);
        }
    }
}
