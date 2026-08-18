package io.aegis.identity.outbox;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A pending business event, staged in the SAME database transaction as the state change it describes
 * — the <b>transactional outbox</b> pattern. This is how identity.user.* events get an at-least-once
 * delivery guarantee they could not have with a best-effort publish.
 *
 * <p><b>The dual-write problem it solves.</b> If a service commits a user to its database and then
 * publishes an event to Kafka as two separate operations, a crash between them loses the event (or,
 * if ordered the other way, publishes an event for a change that rolled back). Writing this row in
 * the same transaction as the user makes "the user exists" and "the event is queued" atomic — either
 * both happen or neither does. A separate relay then moves queued rows to Kafka and marks them
 * published; if the relay crashes after publishing but before marking, it republishes on restart, so
 * delivery is <b>at-least-once</b> and consumers must be idempotent.
 *
 * <p>Deliberately generic (topic + key + JSON payload) so any aggregate can stage events through one
 * outbox and one relay.
 */
@Entity
@Table(name = "outbox_event",
        indexes = @Index(name = "ix_outbox_unpublished", columnList = "published, created_at"))
public class OutboxEvent {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    /** The aggregate this event is about, e.g. {@code user} — for tracing/debugging. */
    @Column(name = "aggregate_type", nullable = false, length = 32)
    private String aggregateType;

    @Column(name = "aggregate_id", nullable = false, length = 64)
    private String aggregateId;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    /** Destination Kafka topic, e.g. {@code aegis.identity.user}. */
    @Column(name = "topic", nullable = false, length = 128)
    private String topic;

    /** Partition key (aggregate id) for per-aggregate ordering. */
    @Column(name = "message_key", nullable = false, length = 64)
    private String messageKey;

    /** JSON payload published to the topic. */
    @Column(name = "payload", nullable = false, columnDefinition = "text")
    private String payload;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "published", nullable = false)
    private boolean published;

    @Column(name = "published_at")
    private Instant publishedAt;

    protected OutboxEvent() {
        // JPA
    }

    public OutboxEvent(String aggregateType, String aggregateId, String eventType, String topic,
                       String messageKey, String payload) {
        this.id = UUID.randomUUID();
        this.aggregateType = aggregateType;
        this.aggregateId = aggregateId;
        this.eventType = eventType;
        this.topic = topic;
        this.messageKey = messageKey;
        this.payload = payload;
        this.createdAt = Instant.now();
        this.published = false;
    }

    public UUID getId() {
        return id;
    }

    public String getTopic() {
        return topic;
    }

    public String getMessageKey() {
        return messageKey;
    }

    public String getPayload() {
        return payload;
    }

    public String getEventType() {
        return eventType;
    }

    public boolean isPublished() {
        return published;
    }

    /** Mark relayed to Kafka. */
    public void markPublished() {
        this.published = true;
        this.publishedAt = Instant.now();
    }
}
