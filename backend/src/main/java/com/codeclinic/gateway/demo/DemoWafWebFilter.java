package com.codeclinic.gateway.demo;

import com.codeclinic.gateway.config.WafProperties;
import com.codeclinic.gateway.detection.FeatureExtractor;
import com.codeclinic.gateway.detection.InferenceClient;
import com.codeclinic.gateway.detection.InferenceResponse;
import com.codeclinic.gateway.log.AttackLog;
import com.codeclinic.gateway.log.AttackLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * demo 프로파일 전용 WAF WebFilter.
 *
 * WafFilter(GlobalFilter)는 Spring Cloud Gateway 라우트 경유 요청에만 동작한다.
 * RPHM(order=0)이 RoutePredicateHandlerMapping(order=1)보다 먼저 /shop/** 컨트롤러를
 * 처리하면 WafFilter가 실행되지 않는다.
 *
 * WebFilter는 DispatcherHandler 이전에 실행되므로 RPHM 경유 컨트롤러 요청도
 * 인터셉트할 수 있다. /shop/** 경로에만 적용하여 WafFilter와 중복 실행되지 않는다.
 */
@Slf4j
@Component
@Profile("demo")
@RequiredArgsConstructor
public class DemoWafWebFilter implements WebFilter, Ordered {

    private final FeatureExtractor  featureExtractor;
    private final InferenceClient   inferenceClient;
    private final WafProperties     wafProperties;
    private final AttackLogService  attackLogService;

    /** Actuator 등 WebFilter보다 먼저 실행되도록 높은 우선순위 설정 */
    @Override
    public int getOrder() {
        return -200;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (!path.startsWith("/shop/")) {
            return chain.filter(exchange);
        }

        return inferenceClient.score(featureExtractor.extract(exchange))
                .flatMap(resp -> evaluate(exchange, chain, resp));
    }

    private Mono<Void> evaluate(ServerWebExchange exchange, WebFilterChain chain, InferenceResponse resp) {
        double score = resp.classificationScore();
        if (score > wafProperties.threshold().block()) {
            return block(exchange, resp);
        }
        if (score > wafProperties.threshold().monitor()) {
            persistLog(exchange, resp, "MONITOR");
        }
        return chain.filter(exchange);
    }

    private Mono<Void> block(ServerWebExchange exchange, InferenceResponse resp) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        persistLog(exchange, resp, "BLOCK");
        return exchange.getResponse().setComplete();
    }

    private void persistLog(ServerWebExchange exchange, InferenceResponse resp, String verdict) {
        String ip = exchange.getRequest().getRemoteAddress() != null
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                : "unknown";

        AttackLog entry = AttackLog.builder()
                .id(UUID.randomUUID())
                .timestamp(Instant.now())
                .sourceIp(ip)
                .method(exchange.getRequest().getMethod().name())
                .uri(exchange.getRequest().getURI().getRawPath())
                .cweType(resp.cweLabel())
                .score(resp.classificationScore())
                .verdict(verdict)
                .rawInput("")
                .build();

        try {
            attackLogService.save(entry);
        } catch (Exception e) {
            log.warn("DemoWafWebFilter: persistLog failed [{}]: {}", e.getClass().getSimpleName(), e.getMessage());
        }
    }
}
