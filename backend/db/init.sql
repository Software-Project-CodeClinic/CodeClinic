-- CodeClinic WAF — TimescaleDB 초기화 스크립트
-- 볼륨이 처음 생성될 때 한 번만 실행됨 (docker-entrypoint-initdb.d)

-- ── 공격 로그 테이블 ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_logs (
    id          UUID             NOT NULL DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    source_ip   TEXT             NOT NULL,
    method      TEXT             NOT NULL,
    uri         TEXT             NOT NULL,
    cwe_type    TEXT,                         -- NORMAL | CWE-89 | CWE-79 | CWE-78 | CWE-22
    score       DOUBLE PRECISION NOT NULL,    -- AI 분류 확률 (0.0 ~ 1.0)
    verdict     TEXT             NOT NULL,    -- BLOCK | MONITOR | PASS
    raw_input   TEXT,                         -- 모델에 전달한 raw HTTP 문자열
    PRIMARY KEY (id, timestamp)               -- hypertable PK에 파티션 키 포함 필수
);

-- hypertable 변환: timestamp 기준으로 자동 파티셔닝 (시계열 범위 쿼리 최적화)
SELECT create_hypertable('attack_logs', 'timestamp');

-- id 단독 UNIQUE 인덱스: recommendations 테이블의 FK 참조를 허용하기 위해 필요
-- (hypertable PK는 복합키(id, timestamp)이므로 id만으로는 FK 참조 불가)
CREATE UNIQUE INDEX ON attack_logs (id);

-- 대시보드 조회 패턴에 맞는 복합 인덱스
CREATE INDEX ON attack_logs (cwe_type, timestamp DESC);
CREATE INDEX ON attack_logs (source_ip, timestamp DESC);

-- ── 권고사항 테이블 (Feedback Bridge 결과 저장) ──────────────────────
CREATE TABLE IF NOT EXISTS recommendations (
    id              BIGSERIAL    PRIMARY KEY,
    attack_log_id   UUID         NOT NULL REFERENCES attack_logs (id),
    cwe_type        TEXT         NOT NULL,
    file_path       TEXT,                     -- SourceLocator가 찾은 .java 파일 경로
    line_number     INT,                      -- Semgrep이 탐지한 취약 라인 번호
    pattern         TEXT,                     -- Semgrep check_id (탐지 규칙 식별자)
    suggestion      TEXT         NOT NULL,    -- RecommendationBuilder 생성 권고 내용
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX ON recommendations (attack_log_id);
CREATE INDEX ON recommendations (cwe_type, created_at DESC);
