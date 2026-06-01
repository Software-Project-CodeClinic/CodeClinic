# 인프라 (백엔드 담당)

> 담당: 태현 / 브랜치: `feat/backend/infra`

## Docker Compose

```yaml
services:
  spring-gateway:
    build: .
    ports: ["8080:8080"]
    depends_on: [timescaledb, fastapi]
    environment:
      AI_SERVER_URL: http://fastapi:8000

  fastapi:
    build: ./ai-server
    ports: ["8000:8000"]

  timescaledb:
    image: timescale/timescaledb:latest-pg15
    environment:
      POSTGRES_PASSWORD: waf
    volumes: ["tsdb_data:/var/lib/postgresql/data"]
    ports: ["5432:5432"]

volumes:
  tsdb_data:
```

## TimescaleDB 초기 설정

```sql
-- attack_logs 테이블을 hypertable로 변환
SELECT create_hypertable('attack_logs', 'timestamp');

-- 자주 쓰는 인덱스
CREATE INDEX ON attack_logs (cwe_type, timestamp DESC);
CREATE INDEX ON attack_logs (source_ip, timestamp DESC);
```

## 패키지 구조

```
com.codeclinic.gateway
├── filter
│   └── WafFilter.java
├── detection
│   ├── FeatureExtractor.java
│   ├── FeatureVector.java
│   ├── InferenceClient.java
│   ├── InferenceResponse.java
│   └── WebClientInferenceClient.java  ← Week 2 (StubInferenceClient 교체)
├── decision
│   ├── DecisionEngine.java
│   ├── DecisionEngineImpl.java        ← Week 2 (StubDecisionEngine 교체)
│   └── Verdict.java
├── log
│   ├── AttackLog.java                 ← Week 2 (JDBC 엔티티)
│   ├── AttackLogRepository.java       ← Week 2
│   ├── AttackLogSavedEvent.java       ← Week 2
│   └── AttackLogService.java          ← Week 2
├── feedback
│   ├── FeedbackBridgeService.java
│   ├── EndpointResolver.java
│   ├── SourceLocator.java
│   ├── SemgrepRunner.java
│   ├── RecommendationBuilder.java
│   ├── Recommendation.java            ← Week 3 (JDBC 엔티티)
│   └── RecommendationRepository.java  ← Week 3
├── api
│   └── DashboardController.java       ← Week 4
├── config
│   ├── AsyncConfig.java               ← Week 2 (waf-async 스레드풀)
│   ├── WafProperties.java             ← Week 2 (@ConfigurationProperties)
│   └── WebClientConfig.java
└── stub
    ├── StubInferenceClient.java   ← Week 2에 삭제
    └── StubDecisionEngine.java    ← Week 2에 삭제
```

## application.yml 주요 설정

`waf.*` 설정은 `WafProperties` record에 `@ConfigurationProperties(prefix = "waf")`로 바인딩됨.

```yaml
waf:
  threshold:
    block: 0.8
    monitor: 0.5
  ai-server:
    url: ${AI_SERVER_URL:http://localhost:8000}
    timeout-ms: 50        # 초과 시 Fail-Open (모든 예외 포함)
  source:
    root: src/main/java   # SourceLocator 기준 경로 (컨테이너: volume mount 경로로 교체)

spring:
  datasource:
    url: jdbc:postgresql://${DB_HOST:localhost}:${DB_PORT:5432}/${DB_NAME:waf}
    username: ${DB_USER:waf}
    password: ${DB_PASSWORD:waf}
```

## Dashboard API 스펙 (Week 4, 인증 없음)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/attacks` | 공격 로그 목록. 쿼리: `cweLabel`, `verdict`, `from`(ISO8601), `to`(ISO8601), `page`, `size` |
| GET | `/api/attacks/{id}` | 단건 상세. `classificationScore`, `rawPayload` 포함 |
| GET | `/api/recommendations` | 권고 목록. 쿼리: `attackLogId` |
| GET | `/api/stats` | 전체 BLOCK/MONITOR 건수, CWE별 분포. 논문 데모 성능 수치 확인용 |

UI는 MVP 범위 밖. API 응답 JSON으로만 결과 확인.

## 통합 테스트 전략 (Week 4)

- `@SpringBootTest(webEnvironment = RANDOM_PORT)`
- `@Testcontainers` + `@Container` : TimescaleDB 인스턴스 실제 구동
- WireMock : FastAPI `/predict` 응답 모킹
- 주요 시나리오:
  - SQLi 페이로드 → BLOCK → attack_logs INSERT → Feedback Bridge 트리거 검증
  - WireMock 응답 지연 60ms → Fail-Open → PASS 검증
  - 정상 트래픽 → PASS → attack_logs 미저장 검증
