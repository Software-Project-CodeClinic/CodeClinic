package com.codeclinic.gateway.detection;

import com.codeclinic.gateway.config.WafProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * FastAPI /predict 엔드포인트를 WebClient로 호출하는 InferenceClient 구현체.
 *
 * Fail-Open 범위: 타임아웃(50ms 초과), Connection refused, HTTP 5xx, JSON 파싱 실패 등
 * 모든 예외를 onErrorResume으로 처리하여 PASS_RESPONSE 반환.
 * 예외 종류는 반드시 log.warn으로 기록 (운영 중 장애 원인 추적 목적).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class WebClientInferenceClient implements InferenceClient {

    private final WebClient    inferenceWebClient;
    private final WafProperties wafProperties;

    @Override
    public Mono<InferenceResponse> score(FeatureVector featureVector) {
        String rawInput = buildRawInput(featureVector);

        return inferenceWebClient.post()
                .uri("/predict")
                .bodyValue(new PredictRequest(rawInput))
                .retrieve()
                .bodyToMono(InferenceResponse.class)
                .timeout(Duration.ofMillis(wafProperties.aiServer().timeoutMs()))
                .doOnError(e -> log.warn("InferenceClient error [{}]: {}", e.getClass().getSimpleName(), e.getMessage()))
                .onErrorReturn(InferenceResponse.PASS_RESPONSE);
    }

    // 인터페이스 계약 형식: {method} {uri} HTTP/1.1\r\n{헤더}\r\n\r\n{body}
    private String buildRawInput(FeatureVector fv) {
        return fv.method() + " " + fv.uri() + " HTTP/1.1\r\n"
             + "User-Agent: "   + fv.userAgent()   + "\r\n"
             + "Content-Type: " + fv.contentType() + "\r\n"
             + "\r\n"
             + fv.rawBody();
    }

    private record PredictRequest(String raw_input) {}
}
