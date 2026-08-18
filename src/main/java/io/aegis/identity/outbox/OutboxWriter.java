package io.aegis.identity.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.stereotype.Component;

/**
 * Stages a business event into the outbox. Callers invoke this from <em>within</em> their existing
 * {@code @Transactional} business method (e.g. user creation), so the event row commits atomically
 * with the state change — the whole point of the outbox.
 *
 * <p>Deliberately has <b>no</b> transaction annotation of its own: it must join the caller's
 * transaction, not start a new one, or the atomicity guarantee is lost.
 */
@Component
public class OutboxWriter {

    private final OutboxEventRepository outbox;
    private final ObjectMapper mapper;

    public OutboxWriter(OutboxEventRepository outbox) {
        this.outbox = outbox;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Stage an event for {@code topic}, keyed by {@code aggregateId}, in the current transaction.
     * Serialisation failure throws — unlike a best-effort publish, a business event we cannot even
     * serialise is a bug that should fail the operation rather than silently drop the event.
     */
    public void stage(String aggregateType, String aggregateId, String eventType, String topic,
                      Object payload) {
        String json;
        try {
            json = mapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialise outbox event " + eventType, e);
        }
        outbox.save(new OutboxEvent(aggregateType, aggregateId, eventType, topic, aggregateId, json));
    }
}
