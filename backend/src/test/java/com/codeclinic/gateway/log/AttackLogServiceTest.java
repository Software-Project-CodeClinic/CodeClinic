package com.codeclinic.gateway.log;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AttackLogServiceTest {

    @Mock private AttackLogRepository       repository;
    @Mock private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private AttackLogService service;

    @Test
    void save_persists_log_to_repository() {
        AttackLog log = buildLog("MONITOR", "CWE-79");

        service.save(log);

        verify(repository).save(log);
    }

    @Test
    void save_publishes_attack_log_saved_event_after_insert() {
        AttackLog log = buildLog("MONITOR", "CWE-79");

        service.save(log);

        ArgumentCaptor<AttackLogSavedEvent> captor = ArgumentCaptor.forClass(AttackLogSavedEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());

        AttackLogSavedEvent event = captor.getValue();
        assertThat(event.attackLogId()).isEqualTo(log.getId());
        assertThat(event.cweLabel()).isEqualTo(log.getCweType());
        assertThat(event.uri()).isEqualTo(log.getUri());
        assertThat(event.method()).isEqualTo(log.getMethod());
        assertThat(event.verdict()).isEqualTo(log.getVerdict());
    }

    @Test
    void save_block_log_publishes_event_with_block_verdict() {
        AttackLog log = buildLog("BLOCK", "CWE-89");

        service.save(log);

        ArgumentCaptor<AttackLogSavedEvent> captor = ArgumentCaptor.forClass(AttackLogSavedEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().verdict()).isEqualTo("BLOCK");
        assertThat(captor.getValue().cweLabel()).isEqualTo("CWE-89");
    }

    @Test
    void save_event_attack_log_id_matches_entity_id() {
        UUID expectedId = UUID.randomUUID();
        AttackLog log = AttackLog.builder()
                .id(expectedId)
                .timestamp(Instant.now())
                .sourceIp("10.0.0.1")
                .method("GET")
                .uri("/api/users")
                .cweType("CWE-22")
                .score(0.65)
                .verdict("MONITOR")
                .rawInput("")
                .build();

        service.save(log);

        ArgumentCaptor<AttackLogSavedEvent> captor = ArgumentCaptor.forClass(AttackLogSavedEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        assertThat(captor.getValue().attackLogId()).isEqualTo(expectedId);
    }

    private AttackLog buildLog(String verdict, String cweType) {
        return AttackLog.builder()
                .id(UUID.randomUUID())
                .timestamp(Instant.now())
                .sourceIp("10.0.0.1")
                .method("GET")
                .uri("/api/users")
                .cweType(cweType)
                .score(0.72)
                .verdict(verdict)
                .rawInput("")
                .build();
    }
}
