package io.aegis.identity.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import io.aegis.identity.domain.AuditEventRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The bridge from identity's domain audit into the platform-wide stream: every {@code record(...)}
 * call must also publish to the shared {@link AuditEventPublisher} (→ log + Kafka → the CloudTrail
 * store), so user/credential lifecycle is visible platform-wide, not only in identity's own table.
 */
class AuditServiceStreamTest {

    private final AuditEventRepository repository = mock(AuditEventRepository.class);
    private final AuditEventPublisher publisher = mock(AuditEventPublisher.class);
    private final AuditService service = new AuditService(repository, publisher);

    @Test
    void a_recorded_event_is_streamed_with_type_identity_and_the_right_fields() {
        service.record("acme", "admin@acme", "USER_DELETED", "bob@acme", "by console");

        ArgumentCaptor<io.aegis.commons.audit.AuditEvent> captor =
                ArgumentCaptor.forClass(io.aegis.commons.audit.AuditEvent.class);
        verify(publisher).publish(captor.capture());
        var event = captor.getValue();

        assertThat(event.type()).isEqualTo("identity");
        assertThat(event.action()).isEqualTo("USER_DELETED");
        assertThat(event.tenantId()).isEqualTo("acme");
        assertThat(event.actor()).isEqualTo("admin@acme");
        assertThat(event.target()).isEqualTo("bob@acme");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.SUCCESS);
    }

    @Test
    void a_failure_action_is_streamed_with_a_failure_outcome() {
        service.record("acme", "alice", "AUTH_FAILURE", "alice", "bad credentials");

        ArgumentCaptor<io.aegis.commons.audit.AuditEvent> captor =
                ArgumentCaptor.forClass(io.aegis.commons.audit.AuditEvent.class);
        verify(publisher).publish(captor.capture());
        assertThat(captor.getValue().outcome()).isEqualTo(AuditOutcome.FAILURE);
    }

    @Test
    void a_blank_tenant_or_action_streams_nothing() {
        service.record("", "alice", "USER_DELETED", null, null);
        service.record("acme", "alice", "", null, null);
        verify(publisher, never()).publish(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void a_missing_actor_defaults_to_system_in_the_stream_too() {
        service.record("acme", null, "POLICY_CHANGED", null, null);

        ArgumentCaptor<io.aegis.commons.audit.AuditEvent> captor =
                ArgumentCaptor.forClass(io.aegis.commons.audit.AuditEvent.class);
        verify(publisher).publish(captor.capture());
        assertThat(captor.getValue().actor()).isEqualTo("system");
    }

    @Test
    void a_publisher_failure_never_propagates_to_the_caller() {
        AuditEventPublisher throwing = e -> {
            throw new RuntimeException("kafka down");
        };
        // Must not throw — audit degrades, never breaks the primary operation.
        new AuditService(repository, throwing).record("acme", "alice", "USER_CREATED", "bob", null);
    }
}
