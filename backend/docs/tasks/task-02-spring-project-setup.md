# T-02 — Spring Boot 프로젝트 생성 + 패키지 구조 확정

> 브랜치: `feat/backend/infra`  
> 의존성: 없음 (T-01과 병렬 진행 가능)

## 목적

Spring Cloud Gateway 기반 프로젝트의 **골격**을 만든다.  
이후 모든 백엔드 작업(T-03, T-04, Week 2~4)이 이 구조 위에서 진행된다.

---

## 구현 항목

### 1. 프로젝트 생성

**Spring Initializr 설정**

| 항목 | 값 |
|------|-----|
| Build tool | Gradle (Kotlin DSL) |
| Language | Java 21 |
| Spring Boot | 3.x (최신 stable) |
| Group | `com.codeclinic` |
| Artifact | `gateway` |
| Packaging | Jar |

**의존성**

| 의존성 | 용도 |
|--------|------|
| `spring-cloud-starter-gateway` | Spring Cloud Gateway (WebFlux 기반) |
| `spring-boot-starter-data-r2dbc` | 비동기 DB 접근 |
| `r2dbc-postgresql` | PostgreSQL R2DBC 드라이버 |
| `spring-boot-starter-validation` | 입력 검증 |
| `spring-boot-starter-actuator` | 헬스체크 |
| `spring-boot-starter-test` | 테스트 |
| `reactor-test` | Reactor 테스트 유틸 |
| `lombok` | 보일러플레이트 제거 |

> R2DBC를 사용하는 이유: Spring Cloud Gateway는 **WebFlux(Netty) 기반**이므로 블로킹 JDBC 사용 불가.

### 2. 패키지 구조

```
backend/src/main/java/com/codeclinic/gateway/
├── filter/
│   └── WafFilter.java              ← T-03
├── detection/
│   ├── FeatureExtractor.java       ← T-04
│   ├── FeatureVector.java          ← T-04 (record)
│   └── InferenceClient.java        ← Week 2
├── decision/
│   ├── DecisionEngine.java         ← Week 2
│   └── Verdict.java                ← Week 2 (enum: BLOCK, MONITOR, PASS)
├── log/
│   ├── AttackLogService.java       ← Week 2
│   ├── AttackLog.java              ← Week 2 (entity)
│   └── AttackLogRepository.java    ← Week 2
├── feedback/
│   ├── FeedbackBridgeService.java  ← Week 3
│   ├── EndpointResolver.java       ← Week 3
│   ├── SourceLocator.java          ← Week 3
│   ├── SemgrepRunner.java          ← Week 3
│   └── RecommendationBuilder.java  ← Week 3
├── api/
│   └── DashboardController.java    ← Week 4
├── config/
│   ├── WebClientConfig.java        ← Week 2
│   └── AsyncConfig.java            ← Week 2
└── GatewayApplication.java
```

### 3. `application.yml` 초안

```yaml
spring:
  application:
    name: codeclinic-gateway
  r2dbc:
    url: r2dbc:postgresql://localhost:5432/waf
    username: ${DB_USER:waf}
    password: ${DB_PASSWORD:waf_local_secret}

server:
  port: 8080

waf:
  threshold:
    block: 0.8
    monitor: 0.5
  ai-server:
    url: ${AI_SERVER_URL:http://localhost:8000}
    timeout-ms: 50
  source:
    root: src/main/java

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

### 4. Upstream Proxy 기본 라우팅

Week 1에서는 WAF 필터 검증용 더미 라우팅만 구성한다.

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: upstream-dummy
          uri: http://httpbin.org   # 로컬 테스트용
          predicates:
            - Path=/**
```

### 5. `GatewayApplication.java`

```java
@SpringBootApplication
@EnableAsync
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
```

---

## 검증 기준

- [ ] `./gradlew bootRun` 으로 앱 기동 (`localhost:8080` 응답)
- [ ] `GET localhost:8080/actuator/health` → `{"status":"UP"}`
- [ ] 패키지 구조가 위 트리와 일치
- [ ] `application.yml`의 모든 시크릿 값이 환경변수 참조 (`${VAR:default}`)
- [ ] `./gradlew test` 컴파일 오류 없음

---

## 주의사항

- **WebFlux + Cloud Gateway**: `spring-boot-starter-web`(서블릿 기반)과 동시 사용 불가 → 의존성에서 제외
- **R2DBC vs JDBC**: Gateway는 Netty 기반이므로 JDBC(블로킹) 사용 시 이벤트 루프 블로킹 발생 — R2DBC 사용 필수
- **@EnableAsync**: `AttackLogService`의 `@Async` 동작을 위해 애플리케이션 시작 시점부터 활성화
