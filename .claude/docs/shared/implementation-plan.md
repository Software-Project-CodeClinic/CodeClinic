# 주차별 구현 계획

## Week 1 — 기반 셋업 + 핫 패스 골격
- Docker Compose 구성 (TimescaleDB, Redis)
- Spring Boot + Cloud Gateway 프로젝트 생성, 패키지 구조 확정
- `WafFilter` 구현 — `cacheRequestBody` body 캐싱 처리 (★ 최우선)
- `FeatureExtractor` 구현 — URI / Header / Body Raw Input 파싱

## Week 2 — AI 추론 연동 + 핫 패스 완성
- FastAPI 추론 서버 — DistilBERT 모델 로드, `/predict` 엔드포인트
- `InferenceClient` — 50ms 타임아웃 + Fail-Open (`onErrorReturn`) (★ 최우선)
- `DecisionEngine` — BLOCK / MONITOR / PASS 3단계 판정, 임계값 `application.yml` 외부화
- `AttackLogService` — `@Async` 비동기 저장, TimescaleDB hypertable 설정

## Week 3 — Feedback Bridge (콜드 패스)
- `EndpointResolver` — URI + Method → Spring 핸들러 메서드 특정
- `SourceLocator` — 핸들러 → `.java` 소스 파일 경로 탐색
- `SemgrepRunner` — ProcessBuilder로 Semgrep CLI 실행, CWE별 규칙셋 자동 선택 (★ stdout/stderr 별도 스레드 소비 필수)
- `RecommendationBuilder` — Semgrep 결과 → 권고 템플릿 매핑 → DB 저장
- `@TransactionalEventListener` 연결 — 로그 커밋 후 Feedback Bridge 트리거

## Week 4 — 통합 검증 + 제출 준비
- `DashboardController` — 공격 로그 / 권고사항 REST API
- 통합 테스트 — SQLi / XSS 페이로드 시나리오, Fail-Open 시나리오 검증
- 논문 4.4절 재현 — CWE-89 탐지 → SourceLocator → PreparedStatement 권고 End-to-End 확인
- Docker Compose 전체 스택 완성 (Spring + FastAPI sidecar + TimescaleDB)
