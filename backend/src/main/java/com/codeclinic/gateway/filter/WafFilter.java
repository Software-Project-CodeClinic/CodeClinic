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
        // cachedRequest를 request로 교체한 exchange를 downstream에 전달해야
        // upstream 서비스가 이미 소비된 원본 body 대신 캐시된 body를 다시 읽을 수 있다.
        return ServerWebExchangeUtils.cacheRequestBody(exchange, cachedRequest -> {
            ServerWebExchange cachedExchange = exchange.mutate().request(cachedRequest).build();
            return Mono.just(featureExtractor.extract(cachedExchange))
                    .flatMap(inferenceClient::score)
                    .flatMap(resp -> decisionEngine.decide(cachedExchange, chain, resp));
        });
    }
}
