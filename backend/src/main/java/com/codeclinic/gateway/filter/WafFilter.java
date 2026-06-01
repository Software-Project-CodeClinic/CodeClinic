package com.codeclinic.gateway.filter;

import com.codeclinic.gateway.decision.DecisionEngine;
import com.codeclinic.gateway.detection.FeatureExtractor;
import com.codeclinic.gateway.detection.InferenceClient;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 모든 HTTP 요청을 가로채는 WAF 진입점 (Hot Path 시작).
 *
 * order=-100: 다른 Gateway 필터보다 반드시 먼저 실행되어야
 * body 소비 전에 cacheRequestBody로 버퍼링을 완료할 수 있다.
 *
 * 처리 체인:
 *   cacheRequestBody → FeatureExtractor → InferenceClient → DecisionEngine
 */
@Component
@RequiredArgsConstructor
public class WafFilter implements GlobalFilter, Ordered {

    private final FeatureExtractor featureExtractor;
    private final InferenceClient  inferenceClient;   // Week 1: Stub / Week 2: WebClient 구현체
    private final DecisionEngine   decisionEngine;    // Week 1: Stub / Week 2: 임계값 판정 구현체

    /** 다른 모든 GlobalFilter보다 먼저 실행되도록 최소값으로 설정 */
    @Override
    public int getOrder() {
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // cacheRequestBody: body를 exchange attribute에 버퍼링한 뒤 mutated request를 람다에 전달.
        // 이 래핑 없이 body를 읽으면 downstream(upstream 서비스)에 빈 body가 전달된다.
        // block() 절대 사용 금지 — WebFlux 이벤트 루프 블로킹 발생.
        return ServerWebExchangeUtils.cacheRequestBody(exchange, cachedRequest ->
                Mono.just(featureExtractor.extract(exchange))   // exchange로 attribute 접근
                    .flatMap(inferenceClient::score)             // AI 추론 (50ms timeout, Fail-Open)
                    .flatMap(resp -> decisionEngine.decide(exchange, chain, resp)) // BLOCK/MONITOR/PASS
        );
    }
}
