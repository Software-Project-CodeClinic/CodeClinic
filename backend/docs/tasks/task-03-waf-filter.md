# T-03 — WafFilter 구현 ★ 최우선

> 브랜치: `feat/backend/waf-filter`  
> 의존성: T-02 (Spring 프로젝트), T-04 (FeatureExtractor)

## 목적

모든 HTTP 요청을 가로채는 **Gateway 진입점**을 구현한다.  
`cacheRequestBody`로 request body를 버퍼링하여 downstream이 빈 body를 수신하는 문제를 방지하고,  
Hot Path 전체 체인(`FeatureExtractor` → `InferenceClient` → `DecisionEngine`)을 Reactive 방식으로 연결한다.

---

## 구현 항목

### 1. `WafFilter.java`

```java
@Component
@RequiredArgsConstructor
public class WafFilter implements GlobalFilter, Ordered {

    private final FeatureExtractor featureExtractor;
    private final InferenceClient inferenceClient;       // Week 2
    private final DecisionEngine decisionEngine;         // Week 2

    @Override
    public int getOrder() { return -100; }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ServerWebExchangeUtils.cacheRequestBody(exchange, cachedRequest ->
            Mono.just(featureExtractor.extract(cachedRequest))
                .flatMap(inferenceClient::score)          // Week 2에서 활성화
                .flatMap(resp -> decisionEngine.decide(exchange, chain, resp))
        );
    }
}
```

#### Week 1 한정 스텁

Week 2(`InferenceClient`, `DecisionEngine`) 미구현 상태에서 컴파일·기동 가능하도록 스텁을 작성한다.

```java
// StubInferenceClient.java — Week 2 전까지만 사용
@Primary
@Component
public class StubInferenceClient implements InferenceClient {
    @Override
    public Mono<InferenceResponse> score(FeatureVector fv) {
        return Mono.just(new InferenceResponse(0.0, "NORMAL"));
    }
}

// StubDecisionEngine.java — Week 2 전까지만 사용
@Primary
@Component
public class StubDecisionEngine implements DecisionEngine {
    @Override
    public Mono<Void> decide(ServerWebExchange ex, GatewayFilterChain chain, InferenceResponse resp) {
        return chain.filter(ex);  // 무조건 PASS
    }
}
```

> `@Primary`를 사용하여 Week 2에서 실제 구현체를 추가하면 스텁이 자동으로 밀려남.  
> Week 2 완료 후 스텁 클래스는 삭제한다.

### 2. 인터페이스 정의

```java
// InferenceClient.java
public interface InferenceClient {
    Mono<InferenceResponse> score(FeatureVector featureVector);
}

// DecisionEngine.java
public interface DecisionEngine {
    Mono<Void> decide(ServerWebExchange exchange, GatewayFilterChain chain, InferenceResponse response);
}

// InferenceResponse.java
public record InferenceResponse(
    double classificationScore,
    String cweLabel
) {}
```

---

## cacheRequestBody 상세

`ServerWebExchangeUtils.cacheRequestBody`의 동작:

1. Request body를 `DataBuffer`로 읽어 exchange attribute에 캐싱
2. 이후 downstream(upstream 서비스)이 같은 body를 다시 읽을 수 있도록 `ServerHttpRequest`를 교체
3. **이 메서드 없이 body를 읽으면 downstream은 빈 body를 수신**하므로 필수

```
[Client 요청]
     │
     ▼
cacheRequestBody ─── body를 메모리에 버퍼링
     │                    │
     │              [exchange attribute에 캐시]
     ▼                    │
FeatureExtractor ─── 캐시된 body 읽기 (원본 소비 없음)
     │
     ▼
[Upstream 서비스] ─── 동일한 body 재소비 가능
```

---

## 검증 기준

- [ ] `GET /api/test` 요청이 `WafFilter`를 통과하여 upstream에 도달
- [ ] `POST /api/test` (body 포함) 요청에서 upstream이 동일한 body를 수신
- [ ] `WafFilter.getOrder()` == -100 확인 (다른 Filter보다 먼저 실행)
- [ ] `FeatureVector`가 정상 생성되는지 단위 테스트 통과
- [ ] 스텁 상태에서 모든 요청이 PASS (403 없음)

### 테스트 시나리오

```java
@SpringBootTest(webEnvironment = RANDOM_PORT)
class WafFilterIntegrationTest {

    @Test
    void post_request_body_reaches_upstream() {
        // POST body가 upstream에 그대로 전달되는지 검증
        // httpbin.org/post 의 json.data 필드로 확인
    }

    @Test
    void feature_vector_is_extracted() {
        // WafFilter가 FeatureVector를 생성하는지 검증
        // 스텁 InferenceClient에 전달된 FeatureVector 캡처
    }
}
```

---

## 주의사항

- **`block()` 절대 금지**: WebFlux 이벤트 루프에서 블로킹 → 전체 서버 응답 지연
- **`cacheRequestBody` 위치**: `filter()` 메서드 최상단에서 즉시 호출해야 함 — 다른 필터가 먼저 body를 소비하지 못하도록 order=-100 설정
- **스텁 삭제 시점**: Week 2에서 실제 `WebClientInferenceClient`, `DecisionEngineImpl` 추가 후 스텁 제거
- **메모리 주의**: 대용량 body(파일 업로드 등)는 DataBufferLimitException 발생 가능 — 필요 시 `maxInMemorySize` 조정
