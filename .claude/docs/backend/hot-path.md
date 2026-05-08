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
        return ServerWebExchangeUtils.cacheRequestBody(exchange, cachedRequest ->
            Mono.just(featureExtractor.extract(exchange))   // ServerWebExchange 전달 (CACHED_REQUEST_BODY_ATTR 접근)
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
    .timeout(Duration.ofMillis(props.aiServer().timeoutMs()))
    .onErrorResume(e -> {
        log.warn("InferenceClient error [{}]: {}", e.getClass().getSimpleName(), e.getMessage());
        return Mono.just(InferenceResponse.PASS_RESPONSE);
    });
```

**Fail-Open 트리거 범위**: 타임아웃(50ms 초과), Connection refused, HTTP 5xx, JSON 파싱 실패 등
모든 예외를 `onErrorResume`으로 통일하여 PASS_RESPONSE 반환.
예외 종류는 반드시 log.warn으로 기록 (운영 중 장애 원인 추적 목적).

⚠ `block()` 절대 사용 금지 — WebFlux 이벤트 루프 블로킹 발생.

## WafProperties (@ConfigurationProperties)

`application.yml`의 `waf.*` 설정을 타입 안전하게 바인딩하는 설정 클래스.

```java
@ConfigurationProperties(prefix = "waf")
public record WafProperties(
    Threshold threshold,
    AiServer  aiServer,
    String    sourceRoot
) {
    public record Threshold(double block, double monitor) {}
    public record AiServer(String url, long timeoutMs) {}
}
```

`GatewayApplication`에 `@EnableConfigurationProperties(WafProperties.class)` 선언 필요.

## DecisionEngine

임계값은 `WafProperties.threshold`를 주입받아 사용.

| 판정 | 조건 | 처리 |
|------|------|------|
| BLOCK | score > 0.8 | 403 즉시 반환 (빈 바디) + attack_logs INSERT (verdict=BLOCK) |
| MONITOR | 0.5 < score ≤ 0.8 | upstream 통과 + attack_logs INSERT (verdict=MONITOR) |
| PASS | score ≤ 0.5 | upstream 프록시, 로그 없음 |

BLOCK 응답은 빈 바디만 반환 — cweLabel, score 등 공격 정보를 응답에 노출하지 않음.

- CWE 레이블은 모델의 argmax 출력을 그대로 사용 (별도 분류 로직 없음)

## AttackLogService (@Async)

BLOCK / MONITOR 판정 시 `DecisionEngineImpl`이 호출. 이벤트 발행까지 포함.

```java
// AsyncConfig — 전용 스레드풀 설정
executor.setCorePoolSize(2);
executor.setMaxPoolSize(10);
executor.setQueueCapacity(100);
executor.setThreadNamePrefix("waf-async-");
```

```java
// AttackLogService
@Transactional
public void save(AttackLog log) {
    repository.save(log);
    eventPublisher.publishEvent(new AttackLogSavedEvent(
        log.getId(), log.getCweType(), log.getUri(), log.getMethod(), log.getVerdict()
    ));
}
```

**AttackLogSavedEvent 필드**: `attackLogId`, `cweLabel`, `uri`, `method`, `verdict`

DB 접근은 JDBC + @Async 조합 — AttackLogService가 waf-async 스레드풀에서 실행되므로
WebFlux 이벤트 루프를 블로킹하지 않음 (R2DBC 미채택).
