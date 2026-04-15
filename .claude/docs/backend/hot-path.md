# Hot Path 상세 (백엔드 담당)

> 담당: 태현 / 브랜치: `feat/backend/waf-filter`, `feat/backend/decision-engine`

## 처리 순서

```
WafFilter (GlobalFilter, order=-100)
  └── cacheRequestBody          ← body 재사용 핵심
       └── FeatureExtractor     ← Raw Input 파싱
            └── InferenceClient ← FastAPI 호출 (50ms timeout)
                 └── DecisionEngine ← BLOCK / MONITOR / PASS
```

## WafFilter

```java
@Component
public class WafFilter implements GlobalFilter, Ordered {
    @Override public int getOrder() { return -100; }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ServerWebExchangeUtils.cacheRequestBody(exchange, req ->
            Mono.just(featureExtractor.extract(req))
                .flatMap(inferenceClient::score)
                .flatMap(resp -> decisionEngine.decide(exchange, chain, resp))
        );
    }
}
```

⚠ `cacheRequestBody` 없이 body를 읽으면 downstream이 빈 body를 수신함.

## FeatureExtractor

- Raw Input 그대로 전달 (URL decode · HTML entity decode · NFKC 정규화 **없음**)
- 모델이 인코딩 패턴까지 학습하므로 정규화 불필요 (논문 3.2절)

```java
public record FeatureVector(
    String method, String uri, String userAgent,
    String contentType, String rawBody, int bodyLength
) {}
```

## InferenceClient

```java
webClient.post().uri("/predict")
    .bodyValue(featureVector)
    .retrieve()
    .bodyToMono(InferenceResponse.class)
    .timeout(Duration.ofMillis(50))
    .onErrorReturn(PASS_RESPONSE);  // Fail-Open
```

⚠ `block()` 절대 사용 금지 — WebFlux 이벤트 루프 블로킹 발생.

## DecisionEngine

```yaml
# application.yml
waf.threshold.block: 0.8
waf.threshold.monitor: 0.5
```

| 판정 | 조건 | 처리 |
|------|------|------|
| BLOCK | score > 0.8 | 403 즉시 반환 + 공격 로그 |
| MONITOR | 0.5 < score ≤ 0.8 | 통과 + 의심 로그 |
| PASS | score ≤ 0.5 | upstream 프록시 |

- CWE 레이블은 모델의 argmax 출력을 그대로 사용 (별도 분류 로직 없음)
