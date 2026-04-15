# 협업 규칙

## 브랜치 전략 — Trunk-Based Development

`main` 브랜치가 항상 최신 상태이며, 짧은 수명의 feature 브랜치를 통해 자주 merge합니다.

```
main  ─────────────────────────────────────────▶  (항상 배포 가능 상태)
        ↑ merge      ↑ merge      ↑ merge
        │            │            │
  feat/backend/ feat/ai/     feat/backend/
  waf-filter    fastapi-server decision-engine
  (1~2일)       (1~2일)       (1~2일)
```

**핵심 원칙**
- 브랜치 수명: **최대 1~2일**. 오래된 브랜치는 충돌과 동기화 문제의 원인
- 하루에 최소 1회 `main` → 내 브랜치로 rebase 또는 merge
- 기능이 완성되지 않아도 feature flag 또는 미완성 상태로 merge 가능
- `main`에 직접 push 금지 (pre-push hook으로 강제)

## 브랜치 네이밍

```
feat/backend/<기능명>       feat/backend/waf-filter
feat/backend/<기능명>       feat/backend/feedback-bridge
feat/ai/<기능명>            feat/ai/fastapi-server
feat/ai/<기능명>            feat/ai/model-training
fix/backend/<버그명>        fix/backend/body-cache-null
fix/ai/<버그명>             fix/ai/timeout-handling
hotfix/<긴급수정명>         hotfix/fail-open-bypass
```

## 파일 소유권 (충돌 방지)

| 경로 | 소유자 | 변경 시 |
|------|--------|---------|
| `backend/src/` | 태현 | 자유롭게 |
| `ai-server/` | 영현 | 자유롭게 |
| `docker-compose.yml` | 태현 주관 | 변경 전 상대방 알림 |
| `.claude/docs/backend/` | 태현 | 자유롭게 |
| `.claude/docs/ai/` | 영현 | 자유롭게 |
| `.claude/docs/shared/` | 공동 | PR 리뷰 필요 |
| `CLAUDE.md` | 공동 | PR 리뷰 필요 |
| `.claude/docs/shared/interface-contract.md` | **공동** | **반드시 양쪽 합의** |

## 인터페이스 계약 변경 시

`/predict` 엔드포인트, `FeatureVector` DTO 등 양쪽이 함께 쓰는 계약 변경:

1. `interface` 레이블 이슈 먼저 생성
2. `interface-contract.md` 수정 PR → 양쪽 approve 후 merge
3. 각자 브랜치에서 동시 반영 후 빠르게 merge

## 커밋 메시지 가이드

```
<type>(<scope>): <제목> (50자 이하)

<본문> (72자 줄바꿈 권장)
- 무엇을 왜 변경했는지 설명
- 어떻게가 아닌 왜에 집중
- 관련 트레이드오프나 고려한 대안 기술

Closes #<이슈번호>
```

**type**

| type | 용도 |
|------|------|
| `feat` | 새 기능 |
| `fix` | 버그 수정 |
| `refactor` | 동작 변경 없는 코드 개선 |
| `docs` | 문서 변경 |
| `test` | 테스트 추가/수정 |
| `chore` | 빌드, 설정, 의존성 |
| `perf` | 성능 개선 |

**scope**

| scope | 담당 |
|-------|------|
| `filter` | WafFilter |
| `detection` | FeatureExtractor, InferenceClient |
| `decision` | DecisionEngine |
| `feedback` | Feedback Bridge 전체 |
| `log` | AttackLogService |
| `infra` | Docker, DB, 설정 |
| `model` | DistilBERT 모델 |
| `api` | FastAPI 서버 |
| `dataset` | 학습 데이터 |
| `docs` | 문서 |

**예시**

```
feat(filter): WafFilter body 캐싱 처리 구현

ServerWebExchangeUtils.cacheRequestBody를 적용해 WebFlux 환경에서
request body를 FeatureExtractor와 downstream 서비스가 모두 읽을 수
있도록 처리함.

단순 exchange.getRequest().getBody() 재사용은 스트림을 소진시켜
downstream이 빈 body를 수신하는 문제가 있어 캐싱 방식 선택.

Closes #12
```

```
fix(feedback): SemgrepRunner stdout 미소비로 인한 프로세스 hang 수정

ProcessBuilder 실행 후 stdout/stderr를 소비하지 않으면 OS 파이프 버퍼가
가득 차 프로세스가 무한 대기 상태에 빠지는 문제 수정.
CompletableFuture로 별도 스레드에서 두 스트림을 동시 소비하도록 변경.

Closes #34
```

```
chore(infra): TimescaleDB hypertable 초기화 스크립트 추가

attack_logs 테이블의 timestamp 컬럼으로 hypertable 생성.
시계열 범위 쿼리(최근 1시간 공격 패턴 등) 성능 향상 목적.
기존 PostgreSQL 단순 테이블 대비 범위 쿼리 약 10x 성능 개선 예상.

Closes #8
```
