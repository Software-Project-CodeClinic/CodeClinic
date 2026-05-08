package com.codeclinic.gateway.stub;

import com.codeclinic.gateway.detection.FeatureVector;
import com.codeclinic.gateway.detection.InferenceClient;
import com.codeclinic.gateway.detection.InferenceResponse;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Week 1 전용 InferenceClient 스텁.
 * AI 서버 없이 컴파일·기동 가능하도록 모든 요청에 PASS_RESPONSE를 반환한다.
 *
 * Week 2에서 WebClientInferenceClient 추가 후 이 클래스 삭제.
 * @Primary: Week 2 구현체 추가 전까지 Spring이 이 Bean을 우선 선택하도록 설정.
 */
@Primary
@Component
class StubInferenceClient implements InferenceClient {

    @Override
    public Mono<InferenceResponse> score(FeatureVector featureVector) {
        // 항상 NORMAL(score=0.0) 반환 → DecisionEngine이 무조건 PASS 처리
        return Mono.just(InferenceResponse.PASS_RESPONSE);
    }
}
