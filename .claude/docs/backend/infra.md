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
com.waf
├── filter
│   └── WafFilter.java
├── detection
│   ├── FeatureExtractor.java
│   └── InferenceClient.java
├── decision
│   └── DecisionEngine.java
├── log
│   └── AttackLogService.java
├── feedback
│   ├── FeedbackBridgeService.java
│   ├── EndpointResolver.java
│   ├── SourceLocator.java
│   ├── SemgrepRunner.java
│   └── RecommendationBuilder.java
├── api
│   └── DashboardController.java
└── config
    └── WebClientConfig.java
```

## application.yml 주요 설정

```yaml
waf:
  threshold:
    block: 0.8
    monitor: 0.5
  ai-server:
    url: http://localhost:8000
    timeout-ms: 50
  source:
    root: src/main/java          # 개발환경 소스 경로

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/waf
```
