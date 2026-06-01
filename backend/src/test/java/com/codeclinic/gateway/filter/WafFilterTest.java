package com.codeclinic.gateway.filter;

import com.codeclinic.gateway.decision.DecisionEngine;
import com.codeclinic.gateway.detection.FeatureExtractor;
import com.codeclinic.gateway.detection.FeatureVector;
import com.codeclinic.gateway.detection.InferenceClient;
import com.codeclinic.gateway.detection.InferenceResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WafFilterTest {

    @Mock private FeatureExtractor featureExtractor;
    @Mock private InferenceClient  inferenceClient;
    @Mock private DecisionEngine   decisionEngine;
    @Mock private GatewayFilterChain chain;

    private WafFilter wafFilter;

    @BeforeEach
    void setUp() {
        wafFilter = new WafFilter(featureExtractor, inferenceClient, decisionEngine);
    }

    @Test
    void order_is_minus_100() {
        // 다른 GlobalFilter보다 먼저 실행되어 body 소비 전에 cacheRequestBody 완료 보장
        assertThat(wafFilter.getOrder()).isEqualTo(-100);
    }

    @Test
    void hot_path_chain_invoked_in_order() {
        // FeatureExtractor → InferenceClient → DecisionEngine 순서로 호출되는지 검증
        FeatureVector    fv   = new FeatureVector("GET", "/api/test", "Mozilla", "", "", 0);
        InferenceResponse resp = InferenceResponse.PASS_RESPONSE;

        when(featureExtractor.extract(any(ServerWebExchange.class))).thenReturn(fv);
        when(inferenceClient.score(fv)).thenReturn(Mono.just(resp));
        when(decisionEngine.decide(any(), any(), eq(resp))).thenReturn(Mono.empty());

        MockServerHttpRequest request  = MockServerHttpRequest.get("/api/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(wafFilter.filter(exchange, chain))
                .verifyComplete();

        verify(featureExtractor).extract(any(ServerWebExchange.class));
        verify(inferenceClient).score(fv);
        verify(decisionEngine).decide(any(), any(), eq(resp));
    }

    @Test
    void stub_state_passes_all_requests_without_403() {
        // Week 1 스텁 상태: InferenceClient는 항상 PASS_RESPONSE, DecisionEngine은 chain.filter() 호출
        FeatureVector fv = new FeatureVector("POST", "/api/admin", "attacker", "text/plain",
                "DROP TABLE users;", 17);

        when(featureExtractor.extract(any(ServerWebExchange.class))).thenReturn(fv);
        when(inferenceClient.score(fv)).thenReturn(Mono.just(InferenceResponse.PASS_RESPONSE));
        when(decisionEngine.decide(any(), any(), any())).thenAnswer(inv -> {
            GatewayFilterChain c      = inv.getArgument(1);
            ServerWebExchange  exch   = inv.getArgument(0);
            return c.filter(exch); // 무조건 PASS
        });
        when(chain.filter(any())).thenReturn(Mono.empty());

        MockServerHttpRequest request  = MockServerHttpRequest.post("/api/admin").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // 완료(Mono.empty)만 방출되고 오류 없어야 함 (403 없음)
        StepVerifier.create(wafFilter.filter(exchange, chain))
                .verifyComplete();
    }
}
