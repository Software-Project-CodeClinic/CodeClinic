package com.codeclinic.gateway.detection;

import reactor.core.publisher.Mono;

/**
 * FastAPI AI 추론 서버 호출 인터페이스.
 * Week 1: StubInferenceClient (항상 PASS_RESPONSE 반환)
 * Week 2: WebClientInferenceClient (실제 HTTP 호출, 50ms timeout + Fail-Open)
 */
public interface InferenceClient {

    Mono<InferenceResponse> score(FeatureVector featureVector);
}
