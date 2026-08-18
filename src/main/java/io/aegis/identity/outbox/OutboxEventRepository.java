package io.aegis.identity.outbox;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Persistence for the outbox. The relay reads unpublished rows oldest-first in bounded batches;
 * writes happen inside the business transaction via {@link OutboxWriter}.
 */
public interface OutboxEventRepository extends JpaRepository<OutboxEvent, UUID> {

    /** Oldest unpublished events first, capped — the relay's work queue. */
    List<OutboxEvent> findByPublishedFalseOrderByCreatedAtAsc(Limit limit);
}
