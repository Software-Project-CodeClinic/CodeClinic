# 테스트 스크립트

## 스크립트 종류

| 스크립트 | 목적 | 필요 서비스 |
|----------|------|-------------|
| `eval_ai.py` | AI 모델 정확도만 측정 (빠름) | AI 서버만 |
| `e2e_test.py` | Hot-Path + Cold-Path 전체 파이프라인 | Docker + AI 서버 + Spring |
| `e2e_test.py --demo` | Cold-Path Recommendation 생성까지 검증 | Docker + AI 서버 + Spring(demo 프로파일) |

---

## 1. AI 정확도만 테스트 (`eval_ai.py`)

### AI 서버 시작
```bash
cd ai-server
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 실행
```bash
# 루트 디렉터리에서
python scripts/eval_ai.py                       # test.csv 전체 (2477건)
python scripts/eval_ai.py --limit 200           # 빠른 검증용
python scripts/eval_ai.py --csv test_with_headers.csv  # 헤더 포함 데이터셋
```

---

## 2. 전체 파이프라인 테스트 (`e2e_test.py`)

### 서비스 기동 순서

**① Docker Desktop 시작** (수동)

**② TimescaleDB**
```bash
docker compose up -d timescaledb
# 헬스체크 통과까지 대기
docker compose ps
```

**③ AI 서버**
```bash
cd ai-server
uvicorn main:app --host 0.0.0.0 --port 8000
```

**④ Spring Gateway**
```bash
cd backend
./gradlew bootRun
# "Started GatewayApplication" 로그 확인
```

### 실행
```bash
# 루트 디렉터리에서
pip install requests psycopg2-binary

python scripts/e2e_test.py                  # 전체 (2477건, 약 5~10분)
python scripts/e2e_test.py --limit 100      # 빠른 검증 (100건)
python scripts/e2e_test.py --no-db-check    # DB 없이 HTTP 응답만 확인
```

---

## 3. Cold-Path Recommendation 생성 검증 (`e2e_test.py --demo`)

### 사전 조건

1. Semgrep 설치: `pip install semgrep`
2. Spring을 **demo 프로파일**로 기동

### 서비스 기동 순서

**① TimescaleDB**
```bash
docker compose up -d timescaledb
```

**② AI 서버**
```bash
cd ai-server
uvicorn main:app --host 0.0.0.0 --port 8000
```

**③ Spring Gateway (demo 프로파일)**
```bash
cd backend
./gradlew bootRun --args='--spring.profiles.active=demo'
```

### 실행

```bash
python scripts/e2e_test.py --demo             # DB 검증 포함 (권장)
python scripts/e2e_test.py --demo --no-db-check  # HTTP 응답만 확인
```

### demo 프로파일 동작 방식

`DemoRoutingConfig`가 `RequestMappingHandlerMapping` 우선순위를 order=2로 낮춘다.
게이트웨이(order=1)가 먼저 처리하므로 WafFilter가 `/shop/**` 경로에도 실행된다.
WafFilter → BLOCK → FeedbackBridgeService → EndpointResolver → SourceLocator → Semgrep → Recommendation 생성.

> **주의**: demo 모드에서 Dashboard API(`/api/**`)는 비작동. 기본 프로파일에서 별도 검증.

---

## 예상 결과

### Hot-Path
- `NORMAL(0)` → 대부분 `PASS/MONITOR` (403 없음)
- `SQLi(1)`, `XSS(2)`, `Path(4)` → score > 0.8이면 `BLOCK(403)`

### Cold-Path
- `attack_logs` 테이블에 BLOCK/MONITOR 건 저장
- `recommendations` 테이블은 **0건 예상** (정상 동작)
  - 이유: 테스트 URI `/tienda1/...`가 Spring 앱 엔드포인트에 없음
  - `EndpointResolver` → `Optional.empty()` → Feedback Bridge graceful 종료

### 50ms 타임아웃 관련
- CPU 환경에서 DistilBERT 추론이 50ms를 초과하면 Fail-Open(PASS) 발생
- 이 경우 재현율(Recall)이 낮아 보임 — 타임아웃 이슈로 판단 가능
- `e2e_test.py`의 ERROR(Fail-Open?) 컬럼으로 구분 가능
