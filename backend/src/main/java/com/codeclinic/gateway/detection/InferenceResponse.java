package com.codeclinic.gateway.detection;

/**
 * FastAPI /predict 응답 DTO.
 * 인터페이스 계약에 따라 classificationScore와 cweLabel 두 필드만 사용.
 */
public record InferenceResponse(
        double classificationScore, // 공격 확률 0.0(정상) ~ 1.0(공격)
        String cweLabel             // NORMAL | CWE-89 | CWE-79 | CWE-78 | CWE-22
) {
    // Fail-Open 기본 응답 — InferenceClient 타임아웃/오류 시 onErrorReturn으로 사용
    public static final InferenceResponse PASS_RESPONSE =
            new InferenceResponse(0.0, "NORMAL");
}
