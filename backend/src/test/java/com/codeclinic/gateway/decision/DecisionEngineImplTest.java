package com.codeclinic.gateway.decision;

import com.codeclinic.gateway.config.WafProperties;
import com.codeclinic.gateway.detection.InferenceResponse;
import com.codeclinic.gateway.log.AttackLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DecisionEngineImplTest {

    @Mock private AttackLogService   attackLogService;
    @Mock private GatewayFilterChain chain;

    private DecisionEngineImpl engine;

    @BeforeEach
    void setUp() {
        WafProperties props = new WafProperties(
                new WafProperties.Threshold(0.8, 0.5),
                new WafProperties.AiServer("http://localhost:8000", 50),
                "src/main/java"
        );
        engine = new DecisionEngineImpl(props, attackLogService);
    }

    // ── BLOCK (score > 0.8) ────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(doubles = {0.81, 0.9, 1.0})
    void score_above_block_threshold_returns_403_and_logs(double score) {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

        StepVerifier.create(engine.decide(exchange, chain, new InferenceResponse(score, "CWE-89")))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(attackLogService).save(any());
        verifyNoInteractions(chain);
    }

    @Test
    void score_exactly_at_block_threshold_is_monitor_not_block() {
        // 0.8 is not strictly greater than 0.8 → classify() falls through to MONITOR check
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
        when(chain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(engine.decide(exchange, chain, new InferenceResponse(0.8, "CWE-89")))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
        verify(chain).filter(any());
        verify(attackLogService).save(any());
    }

    // ── MONITOR (0.5 < score <= 0.8) ──────────────────────────────────────

    @ParameterizedTest
    @ValueSource(doubles = {0.51, 0.7, 0.8})
    void score_in_monitor_range_passes_upstream_and_logs(double score) {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
        when(chain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(engine.decide(exchange, chain, new InferenceResponse(score, "CWE-79")))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
        verify(chain).filter(any());
        verify(attackLogService).save(any());
    }

    @Test
    void score_exactly_at_monitor_threshold_is_pass_not_monitor() {
        // 0.5 is not strictly greater than 0.5 → PASS
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
        when(chain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(engine.decide(exchange, chain, new InferenceResponse(0.5, "NORMAL")))
                .verifyComplete();

        verify(chain).filter(any());
        verifyNoInteractions(attackLogService);
    }

    // ── PASS (score <= 0.5) ────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(doubles = {0.0, 0.3, 0.5})
    void score_at_or_below_monitor_threshold_passes_without_log(double score) {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
        when(chain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(engine.decide(exchange, chain, new InferenceResponse(score, "NORMAL")))
                .verifyComplete();

        verify(chain).filter(any());
        verifyNoInteractions(attackLogService);
    }

    // ── Verdict log field ─────────────────────────────────────────────────

    @Test
    void block_verdict_saves_log_with_block_verdict_string() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/login").build());

        engine.decide(exchange, chain, new InferenceResponse(0.95, "CWE-89")).block();

        var captor = org.mockito.ArgumentCaptor.forClass(com.codeclinic.gateway.log.AttackLog.class);
        verify(attackLogService).save(captor.capture());
        assertThat(captor.getValue().getVerdict()).isEqualTo("BLOCK");
        assertThat(captor.getValue().getCweType()).isEqualTo("CWE-89");
    }

    @Test
    void monitor_verdict_saves_log_with_monitor_verdict_string() {
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/data").build());
        when(chain.filter(any())).thenReturn(Mono.empty());

        engine.decide(exchange, chain, new InferenceResponse(0.72, "CWE-79")).block();

        var captor = org.mockito.ArgumentCaptor.forClass(com.codeclinic.gateway.log.AttackLog.class);
        verify(attackLogService).save(captor.capture());
        assertThat(captor.getValue().getVerdict()).isEqualTo("MONITOR");
        assertThat(captor.getValue().getCweType()).isEqualTo("CWE-79");
    }
}
