package com.codeclinic.gateway.stub;

import com.codeclinic.gateway.decision.DecisionEngine;
import com.codeclinic.gateway.detection.InferenceResponse;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Week 1 전용 DecisionEngine 스텁.
 * InferenceResponse에 관계없이 모든 요청을 upstream으로 통과시킨다.
 *
 * Week 2에서 DecisionEngineImpl 추가 후 이 클래스 삭제.
 * @Primary: Week 2 구현체 추가 전까지 Spring이 이 Bean을 우선 선택하도록 설정.
 */
@Primary
@Component
class StubDecisionEngine implements DecisionEngine {

    @Override
    public Mono<Void> decide(ServerWebExchange exchange, GatewayFilterChain chain, InferenceResponse response) {
        // 판정 없이 무조건 PASS — 필터 체인 다음 단계(upstream 프록시)로 진행
        return chain.filter(exchange);
    }
}
