package com.codeclinic.gateway.decision;

import com.codeclinic.gateway.config.WafProperties;
import com.codeclinic.gateway.detection.InferenceResponse;
import com.codeclinic.gateway.log.AttackLog;
import com.codeclinic.gateway.log.AttackLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * WafProperties의 임계값을 기반으로 BLOCK / MONITOR / PASS를 판정한다.
 *
 * BLOCK  (score > threshold.block)   : 403 반환 (빈 바디) + attack_logs INSERT
 * MONITOR(score > threshold.monitor) : upstream 통과 + attack_logs INSERT
 * PASS   (그 외)                     : upstream 통과, 로그 없음
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DecisionEngineImpl implements DecisionEngine {

    private final WafProperties    wafProperties;
    private final AttackLogService attackLogService;

    @Override
    public Mono<Void> decide(ServerWebExchange exchange, GatewayFilterChain chain, InferenceResponse response) {
        Verdict verdict = classify(response.classificationScore());

        return switch (verdict) {
            case BLOCK   -> block(exchange, response);
            case MONITOR -> monitor(exchange, chain, response);
            case PASS    -> chain.filter(exchange);
        };
    }

    private Verdict classify(double score) {
        if (score > wafProperties.threshold().block())   return Verdict.BLOCK;
        if (score > wafProperties.threshold().monitor()) return Verdict.MONITOR;
        return Verdict.PASS;
    }

    private Mono<Void> block(ServerWebExchange exchange, InferenceResponse response) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        saveLog(exchange, response, Verdict.BLOCK);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> monitor(ServerWebExchange exchange, GatewayFilterChain chain, InferenceResponse response) {
        saveLog(exchange, response, Verdict.MONITOR);
        return chain.filter(exchange);
    }

    private void saveLog(ServerWebExchange exchange, InferenceResponse response, Verdict verdict) {
        String remoteAddress = exchange.getRequest().getRemoteAddress() != null
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                : "unknown";

        AttackLog log = AttackLog.builder()
                .id(UUID.randomUUID())
                .timestamp(Instant.now())
                .sourceIp(remoteAddress)
                .method(exchange.getRequest().getMethod().name())
                .uri(exchange.getRequest().getURI().getRawPath())
                .cweType(response.cweLabel())
                .score(response.classificationScore())
                .verdict(verdict.name())
                .rawInput("")   // FeatureExtractor에서 buildRawInput()로 구성 가능하나 hot-path 지연 최소화를 위해 생략
                .build();

        attackLogService.save(log);
    }
}
