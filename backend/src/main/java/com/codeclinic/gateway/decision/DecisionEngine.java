package com.codeclinic.gateway.decision;

import com.codeclinic.gateway.detection.InferenceResponse;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * AI 추론 결과를 바탕으로 BLOCK / MONITOR / PASS를 판정하는 인터페이스.
 * Week 1: StubDecisionEngine (모든 요청 PASS)
 * Week 2: DecisionEngineImpl (임계값 기반 실제 판정 + AttackLogService 호출)
 */
public interface DecisionEngine {

    Mono<Void> decide(ServerWebExchange exchange, GatewayFilterChain chain, InferenceResponse response);
}
