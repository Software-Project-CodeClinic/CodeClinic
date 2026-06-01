# Week 1 구현 계획 — 기반 셋업 + Hot Path 골격

> 담당: 태현 / 브랜치: `feat/backend/infra`, `feat/backend/waf-filter`

## 목표

Spring Cloud Gateway 기반 WAF의 **Hot Path 골격**을 완성한다.  
Week 2에서 AI 추론 연동(`InferenceClient`, `DecisionEngine`)을 붙일 수 있는 상태로 마무리.

---

## 작업 목록

| # | 작업 | 브랜치 | 의존성 | 우선순위 |
|---|------|--------|--------|---------|
| T-01 | Docker Compose 구성 (TimescaleDB, Redis) | `feat/backend/infra` | 없음 | 보통 |
| T-02 | Spring Boot 프로젝트 생성 + 패키지 구조 확정 | `feat/backend/infra` | 없음 | 보통 |
| T-03 | `WafFilter` 구현 (`cacheRequestBody` 포함) | `feat/backend/waf-filter` | T-04 | ★ 최우선 |
| T-04 | `FeatureExtractor` 구현 (Raw Input 파싱) | `feat/backend/waf-filter` | T-02 | 보통 |

### 실행 순서

```text
T-01 ──┐
       ├── (병렬 가능)
T-02 ──┘
        └─► T-04 ──► T-03
```

T-01과 T-02는 독립적으로 병렬 진행 가능.  
T-03(`WafFilter`)은 T-04(`FeatureExtractor`)를 내부에서 호출하므로 T-04 완료 후 구현.

---

## 결과물 기준 (Week 1 완료 조건)

- [ ] `docker compose up -d` 로 TimescaleDB, Redis 컨테이너 정상 기동
- [ ] `hypertable` 생성 SQL이 init 스크립트에 포함되어 자동 실행
- [ ] Spring Boot 앱이 `localhost:8080` 에서 기동되고 upstream 프록시 동작
- [ ] HTTP 요청을 `WafFilter`가 가로채어 `FeatureVector`를 생성할 수 있음
- [ ] `raw_input` 문자열이 인터페이스 계약 형식대로 조합됨
- [ ] `@SpringBootTest` 슬라이스 테스트 1건 이상 통과

---

## 세부 계획 문서

| 문서 | 내용 |
|------|------|
| [task-01-docker-compose.md](tasks/task-01-docker-compose.md) | Docker Compose 구성 세부 계획 |
| [task-02-spring-project-setup.md](tasks/task-02-spring-project-setup.md) | Spring Boot 프로젝트 셋업 세부 계획 |
| [task-03-waf-filter.md](tasks/task-03-waf-filter.md) | WafFilter 구현 세부 계획 |
| [task-04-feature-extractor.md](tasks/task-04-feature-extractor.md) | FeatureExtractor 구현 세부 계획 |

---

## 핵심 제약사항 (공통)

- **Raw Input**: 인코딩 정규화(URL decode, HTML entity decode, NFKC) **절대 금지**
- **block() 금지**: WebFlux 이벤트 루프에서 blocking I/O 호출 금지
- **설정 외부화**: 임계값, URL 등 모든 설정은 `application.yml` + 환경변수
- **시크릿 하드코딩 금지**: DB 패스워드 등은 환경변수로만 주입
