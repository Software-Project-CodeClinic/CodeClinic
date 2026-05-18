# T-01 — Docker Compose 구성 (TimescaleDB, Redis)

> 브랜치: `feat/backend/infra`  
> 의존성: 없음 (T-02와 병렬 진행 가능)

## 목적

개발 환경에서 Spring Gateway와 FastAPI가 사용하는 **외부 서비스(DB, 캐시)를 컨테이너로 격리**한다.  
Week 4 전체 스택 통합 시 이 Compose 파일을 그대로 확장해 사용한다.

---

## 구현 항목

### 1. `docker-compose.yml` 작성

포함할 서비스:

| 서비스 | 이미지 | 포트 | 비고 |
|--------|--------|------|------|
| `timescaledb` | `timescale/timescaledb:2.18.0-pg15` | `5432:5432` | 공격 로그 저장소 |
| `redis` | `redis:7-alpine` | `6379:6379` | (Week 2 이후 사용 예정, 선 구성) |

Week 1에서 `spring-gateway`, `fastapi` 서비스는 **주석 처리**로 남긴다.  
(Week 2~4에서 순차적으로 활성화)

### 2. TimescaleDB 초기화 스크립트 (`init.sql`)

자동 실행 위치: `/docker-entrypoint-initdb.d/`

```sql
CREATE DATABASE waf;
\c waf

CREATE TABLE IF NOT EXISTS attack_logs (
    id          UUID            NOT NULL DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    source_ip   TEXT            NOT NULL,
    method      TEXT            NOT NULL,
    uri         TEXT            NOT NULL,
    cwe_type    TEXT,
    score       DOUBLE PRECISION NOT NULL,
    verdict     TEXT            NOT NULL,   -- BLOCK | MONITOR | PASS
    raw_input   TEXT,
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('attack_logs', 'timestamp');

CREATE INDEX ON attack_logs (cwe_type, timestamp DESC);
CREATE INDEX ON attack_logs (source_ip, timestamp DESC);

CREATE TABLE IF NOT EXISTS recommendations (
    id              UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    attack_log_id   UUID        NOT NULL,
    cwe_type        TEXT        NOT NULL,
    file_path       TEXT,
    line_number     INT,
    pattern         TEXT        NOT NULL,
    suggestion      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

> `attack_logs`의 PK에 `timestamp`를 포함하는 이유: TimescaleDB hypertable은 파티션 키가 PK에 포함되어야 한다.

### 3. 환경변수 분리 (`.env`)

```dotenv
POSTGRES_DB=waf
POSTGRES_USER=waf
POSTGRES_PASSWORD=waf_local_secret
```

`.env` 파일은 `.gitignore`에 추가. `docker-compose.yml`은 `${변수명}` 참조.

---

## 검증 기준

- [ ] `docker compose up -d timescaledb redis` 실행 후 두 컨테이너 `Healthy` 상태
- [ ] `psql -h localhost -U waf -d waf -c "\dt"` 로 `attack_logs`, `recommendations` 테이블 확인
- [ ] `SELECT * FROM timescaledb_information.hypertables;` 에서 `attack_logs` 조회됨
- [ ] `redis-cli ping` → `PONG` 응답

---

## 주의사항

- `.env` 파일을 커밋하지 않는다 (`.gitignore` 등록 필수)
- TimescaleDB init 스크립트는 볼륨이 **처음 생성될 때만** 실행된다 — 스키마 변경 시 볼륨 삭제 후 재실행 필요
- `timescale/timescaledb:2.18.0-pg15` 이미지는 `pg_isready` health check 지원 → `depends_on` 활용 시 `condition: service_healthy` 사용
