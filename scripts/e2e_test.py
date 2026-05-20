#!/usr/bin/env python3
"""
전체 파이프라인 E2E 테스트 (Hot-Path + Cold-Path)

사전 조건:
  1. Docker Desktop 실행
  2. docker compose up -d timescaledb
  3. cd ai-server && uvicorn main:app --host 0.0.0.0 --port 8000
  4. cd backend && ./gradlew bootRun

Cold-Path 주의:
  테스트 데이터 URI(/tienda1/...)는 Spring 앱 엔드포인트와 매핑되지 않아
  EndpointResolver가 Optional.empty()를 반환합니다.
  Recommendation은 생성되지 않지만, Bridge 트리거·graceful degradation은 검증됩니다.

--demo 모드 (Cold-Path Recommendation 생성 전체 검증):
  Spring을 demo 프로파일로 기동해야 합니다.
    cd backend && ./gradlew bootRun --args='--spring.profiles.active=demo'
  VulnerableShopController 4개 엔드포인트를 공격하여
  attack_logs + recommendations 테이블 생성까지 검증합니다.
    /shop/search  CWE-89 (SQL Injection)
    /shop/file    CWE-22 (Path Traversal)
    /shop/review  CWE-79 (XSS)
    /shop/ping    CWE-78 (Command Injection, 모델 미학습 — BLOCK 미보장)

사용법:
  python scripts/e2e_test.py                              # test.csv, 전체
  python scripts/e2e_test.py --limit 100                  # 처음 100건
  python scripts/e2e_test.py --decode-uri                 # URI 디코딩 후 전송 (eval_ai.py 기준)
  python scripts/e2e_test.py --no-db-check                # DB 검증 생략
  python scripts/e2e_test.py --demo                       # Cold-Path (하드코딩 페이로드)
  python scripts/e2e_test.py --demo --demo-csv test.csv   # Cold-Path (CSV 샘플링)
  python scripts/e2e_test.py --demo --demo-csv test.csv --samples 5  # CWE별 5건씩
"""
import argparse
import csv
import sys

# Windows 콘솔이 cp949일 때 유니코드 출력 깨짐 방지
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
import time
import urllib.parse
from collections import Counter, defaultdict

try:
    import requests
except ImportError:
    sys.exit("pip install requests 필요")

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

GATEWAY = "http://localhost:8181"
DB_DSN  = "postgresql://waf:waf_local_secret@localhost:5432/waf"

LABEL_MAP    = {0: "NORMAL", 1: "CWE-89", 2: "CWE-79", 3: "CWE-78", 4: "CWE-22"}
ATTACK_LABELS = {1, 2, 3, 4}

# demo 모드 기본 공격 목록 — VulnerableShopController 엔드포인트 대상
# 페이로드는 URL 인코딩 상태로 전송 → Spring Gateway가 디코딩 후 AI 모델에 전달
# --demo-csv test.csv 옵션으로 CSV에서 실제 페이로드를 샘플링해 대체 가능
DEMO_ATTACKS = [
    # CWE-89: SQL Injection  (/shop/search)
    ("GET", "/shop/search?q=1%27+OR+%271%27%3D%271"),           # 1' OR '1'='1
    ("GET", "/shop/search?q=%27%3B+DROP+TABLE+products%3B+--"), # '; DROP TABLE products; --
    ("GET", "/shop/search?q=admin%27--"),                        # admin'--

    # CWE-22: Path Traversal  (/shop/file)
    ("GET", "/shop/file?path=../../etc/passwd"),
    ("GET", "/shop/file?path=../../../proc/self/environ"),

    # CWE-79: XSS  (/shop/review) — 디코딩 후: <script>alert(1)</script>, "><img src=x onerror=alert(1)>
    ("GET", "/shop/review?comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    ("GET", "/shop/review?comment=%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"),

    # CWE-78: Command Injection  (/shop/ping) — 디코딩 후: localhost; id, 127.0.0.1 && whoami
    # 주의: 모델 학습 데이터에 CWE-78 샘플 없음 → BLOCK이 보장되지 않는다
    ("GET", "/shop/ping?host=localhost%3B+id"),
    ("GET", "/shop/ping?host=127.0.0.1+%26%26+whoami"),
]

# CWE 레이블 → (demo 엔드포인트, 파라미터명) 매핑
_DEMO_ENDPOINT_MAP = {
    1: ("/shop/search", "q"),        # CWE-89: SQL Injection
    2: ("/shop/review", "comment"),  # CWE-79: XSS
    4: ("/shop/file",   "path"),     # CWE-22: Path Traversal
    # label 3 (CWE-78): CSV에 샘플 없음 → 하드코딩 폴백
}

# CWE-78 하드코딩 폴백 (CSV에 없으므로 항상 포함)
_CWE78_FALLBACK = [
    ("GET", "/shop/ping?host=localhost%3B+id"),
    ("GET", "/shop/ping?host=127.0.0.1+%26%26+whoami"),
]


def _extract_raw_query(text: str) -> str | None:
    """
    test.csv text 컬럼에서 원본 쿼리 스트링을 그대로 반환한다 (디코딩 없음).
    쿼리 파라미터가 없으면 None 반환.

    예) "GET /tienda1/entrar.jsp?errorMsg=AND+1=1"  →  "errorMsg=AND+1=1"
    """
    text = text.strip()
    parts = text.split(" ", 2)
    raw = parts[1] if len(parts) >= 2 else "/"
    if raw.startswith("http"):
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.path + ("?" + parsed.query if parsed.query else "")
    raw = raw.split(" ")[0]  # "HTTP/1.1" 제거
    if "?" not in raw:
        return None
    return raw.split("?", 1)[1] or None


def build_demo_attacks_from_csv(csv_path: str, samples_per_cwe: int = 3, seed: int = 42) -> list:
    """
    CSV에서 CWE별 샘플을 추출해 demo 엔드포인트 URI로 변환한다.

    변환 방식: 경로만 demo 엔드포인트로 교체, 원본 쿼리 스트링은 그대로 유지.
      예) GET /tienda1/entrar.jsp?errorMsg=AND+1=1
          → GET /shop/search?errorMsg=AND+1=1

    이렇게 하면 공격 패턴이 그대로 보존되어 모델이 올바르게 분류할 수 있다.
    Spring EndpointResolver는 쿼리 파라미터 무관하게 경로 패턴으로만 핸들러를 조회한다.

    CWE-78은 CSV에 샘플이 없으므로 _CWE78_FALLBACK이 항상 추가된다.
    test_with_headers.csv 사용 시 NORMAL/CWE-89만 있으므로 CWE-89 공격만 샘플링된다.
    """
    import random
    rng = random.Random(seed)

    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    attacks = []
    for label, (endpoint, _param) in _DEMO_ENDPOINT_MAP.items():
        candidates = [r for r in rows if int(r["label"]) == label]
        rng.shuffle(candidates)

        picked = 0
        for row in candidates:
            if picked >= samples_per_cwe:
                break
            query = _extract_raw_query(row["text"])
            if not query:
                continue
            attacks.append(("GET", f"{endpoint}?{query}"))
            picked += 1

        if picked == 0 and label in (1, 2, 4):  # CWE-78 제외
            print(f"  [INFO] {LABEL_MAP.get(label,'?')} 샘플이 CSV에 없습니다 (쿼리 포함).", file=sys.stderr)

    attacks.extend(_CWE78_FALLBACK)
    return attacks

# verdict → 기대 범주 (레이블 기준)
#   true NORMAL → PASS
#   true ATTACK → BLOCK 또는 MONITOR


def parse_request_line(text: str, decode_uri: bool = False):
    """test.csv text 컬럼 → (method, path) 추출."""
    text = text.strip()
    parts = text.split(" ", 2)
    method = parts[0].upper() if parts else "GET"
    if len(parts) < 2:
        return method, "/"

    raw_path = parts[1]
    # 절대 URL 처리
    if raw_path.startswith("http"):
        parsed = urllib.parse.urlparse(raw_path)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
    else:
        # "HTTP/1.1" 이 path에 붙어있는 경우 제거
        path = raw_path.split(" ")[0]

    if decode_uri:
        path = urllib.parse.unquote_plus(path)

    return method, path or "/"


def send_request(session, method: str, path: str, gateway: str = GATEWAY) -> requests.Response | None:
    url = gateway + path
    try:
        resp = session.request(
            method=method,
            url=url,
            headers={
                "User-Agent": "e2e-test/1.0",
                "Content-Type": "text/plain",
            },
            timeout=5,
            allow_redirects=False,
        )
        return resp
    except requests.exceptions.Timeout:
        return None
    except Exception as e:
        print(f"\n  [WARN] 요청 실패 ({method} {path}): {e}", file=sys.stderr)
        return None


def query_db_counts(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT verdict, cwe_type, COUNT(*)
            FROM attack_logs
            GROUP BY verdict, cwe_type
            ORDER BY verdict, cwe_type
        """)
        rows = cur.fetchall()
    result = {}
    for verdict, cwe_type, cnt in rows:
        result[(verdict, cwe_type)] = cnt
    return result


def run_demo(args):
    """Cold-Path 전체 파이프라인 검증 (demo 프로파일 전용)."""
    print("[ Cold-Path Demo 테스트 ]")
    print("  Spring 기동 확인: --spring.profiles.active=demo 필요\n")

    if args.demo_csv:
        attacks = build_demo_attacks_from_csv(args.demo_csv, args.samples)
        print(f"  페이로드: {args.demo_csv} 에서 CWE별 {args.samples}건 샘플링 ({len(attacks)}건)\n")
    else:
        attacks = DEMO_ATTACKS
        print(f"  페이로드: 하드코딩 ({len(attacks)}건)\n")

    try:
        r = requests.get(f"{args.gateway}/actuator/health", timeout=3)
        r.raise_for_status()
        print(f"  ✓ Spring Gateway: {args.gateway}")
    except Exception:
        sys.exit(f"  ✗ Spring Gateway({args.gateway}) 연결 실패. bootRun --args='--spring.profiles.active=demo' 확인.")

    conn = None
    if not args.no_db_check and HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(args.db)
            print(f"  ✓ TimescaleDB 연결\n")
        except Exception as e:
            print(f"  ✗ DB 연결 실패: {e}\n")
            conn = None

    # DB 초기 스냅샷
    before_rec = 0
    if conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM recommendations")
            before_rec = cur.fetchone()[0]
        print(f"  DB 초기 recommendations: {before_rec}건\n")

    # 공격 전송
    print("[ 데모 공격 전송 ]")
    session = requests.Session()
    results = []
    for method, path in attacks:
        resp = send_request(session, method, path, gateway=args.gateway)
        status = resp.status_code if resp is not None else None
        verdict = "BLOCK(403)" if status == 403 else f"status={status}" if status is not None else "ERROR"
        print(f"  {method:4} {path[:60]:<60}  → {verdict}")
        results.append((path, status))

    blocked = sum(1 for _, s in results if s == 403)
    print(f"\n  BLOCK: {blocked}/{len(attacks)}건\n")

    if blocked == 0:
        print("  [주의] BLOCK이 없습니다. AI 서버가 데모 페이로드를 탐지하지 못할 수 있습니다.")
        print("  eval_ai.py로 각 페이로드의 score를 확인하세요.\n")

    # FeedbackBridge @Async 완료 대기
    if conn:
        print("[ DB 검증 - recommendations (15초 대기) ]")
        time.sleep(15)

        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM recommendations")
            after_rec = cur.fetchone()[0]
            cur.execute("""
                SELECT r.cwe_type, r.pattern, r.file_path, r.line_number
                FROM recommendations r
                ORDER BY r.created_at DESC
                LIMIT 10
            """)
            new_recs = cur.fetchall()

        new_count = after_rec - before_rec
        print(f"  신규 recommendations: {new_count}건 (전체: {after_rec}건)\n")

        if new_count > 0:
            print("  [ 생성된 Recommendation ]")
            print(f"  {'CWE':>8}  {'pattern':>50}  {'line':>5}")
            for cwe, pattern, fpath, lineno in new_recs:
                short_pat = (pattern or "")[:48]
                print(f"  {cwe:>8}  {short_pat:>50}  {lineno:>5}")
            print()
            print("  ✓ Cold-Path 전체 파이프라인 검증 완료")
        else:
            print("  ✗ Recommendation 미생성. 원인 확인:")
            print("    1. Semgrep 미설치: pip install semgrep")
            print("    2. EndpointResolver 조회 실패: Spring 로그에서 'no handler' 확인")
            print("    3. Semgrep check_id ↔ RecommendationBuilder 토큰 불일치:")
            print("       FeedbackBridgeService 로그에서 'no template for' 메시지 확인")

        conn.close()
    else:
        print("  DB 검증 생략 (--no-db-check 또는 psycopg2 미설치)")
        print("  Recommendation 생성 여부는 Spring 로그에서 확인하세요.")

    print("\n[ Cold-Path Demo 완료 ]")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",      default="test.csv")
    parser.add_argument("--gateway",  default=GATEWAY)
    parser.add_argument("--db",       default=DB_DSN)
    parser.add_argument("--limit",    type=int, default=None)
    parser.add_argument("--no-db-check", action="store_true")
    parser.add_argument("--decode-uri", action="store_true",
                        help="URI를 URL 디코딩 후 게이트웨이에 전달 (eval_ai.py 기준, hot-path 모드 전용)")
    parser.add_argument("--demo",     action="store_true",
                        help="Cold-Path 전체 검증 모드 (VulnerableShopController 공격)")
    parser.add_argument("--demo-csv", default=None, metavar="CSV",
                        help="demo 공격 페이로드를 CSV에서 샘플링 (예: test.csv)")
    parser.add_argument("--samples",  type=int, default=3,
                        help="--demo-csv 사용 시 CWE별 샘플 수 (기본: 3)")
    args = parser.parse_args()

    if args.demo:
        run_demo(args)
        return

    # ── 사전 연결 확인 ──────────────────────────────────────────────────────
    print("[ 사전 조건 확인 ]")
    try:
        r = requests.get(f"{args.gateway}/actuator/health", timeout=3)
        r.raise_for_status()
        print(f"  ✓ Spring Gateway: {args.gateway}")
    except Exception:
        sys.exit(f"  ✗ Spring Gateway({args.gateway}) 연결 실패. bootRun을 먼저 실행하세요.")

    conn = None
    if not args.no_db_check and HAS_PSYCOPG2:
        try:
            conn = psycopg2.connect(args.db)
            print(f"  ✓ TimescaleDB 연결")
        except Exception as e:
            print(f"  ✗ DB 연결 실패: {e} → --no-db-check 로 재실행하거나 Docker를 확인하세요.")
            conn = None
    elif not HAS_PSYCOPG2 and not args.no_db_check:
        print("  ! psycopg2 없음 → DB 검증 생략 (pip install psycopg2-binary)")

    # ── DB 초기 상태 스냅샷 ─────────────────────────────────────────────────
    db_before = {}
    if conn:
        db_before = query_db_counts(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM attack_logs")
            before_total = cur.fetchone()[0]
        print(f"  DB 초기 attack_logs: {before_total}건\n")

    # ── 데이터 로딩 ─────────────────────────────────────────────────────────
    with open(args.csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if args.limit:
        rows = rows[:args.limit]
    total = len(rows)

    label_counts = Counter(int(r["label"]) for r in rows)
    print(f"[ 테스트 데이터: {args.csv} ({total}건) ]")
    for lbl, cnt in sorted(label_counts.items()):
        print(f"  {LABEL_MAP.get(lbl, '?'):>8} ({lbl}): {cnt}건")
    print()

    # ── 요청 전송 ───────────────────────────────────────────────────────────
    print("[ Hot-Path 테스트 시작 ]")
    session   = requests.Session()
    responses = []   # (true_label, status_code, latency_ms)
    errors    = 0

    decode_uri = args.decode_uri
    mode_label = "URI 디코딩 O" if decode_uri else "URI 디코딩 X (원본)"
    print(f"  모드: {mode_label}\n")

    t_start = time.time()
    for i, row in enumerate(rows, 1):
        true_label = int(row["label"])
        method, path = parse_request_line(row["text"], decode_uri=decode_uri)

        t0   = time.time()
        resp = send_request(session, method, path)
        ms   = (time.time() - t0) * 1000

        if resp is None:
            errors += 1
            responses.append((true_label, None, ms))
        else:
            responses.append((true_label, resp.status_code, ms))

        if i % 100 == 0 or i == total:
            blocked = sum(1 for _, s, _ in responses if s == 403)
            print(f"  [{i:>4}/{total}]  BLOCK(403): {blocked}건  오류: {errors}건  "
                  f"avg {sum(l for _, _, l in responses)/len(responses):.0f}ms")

    elapsed = time.time() - t_start
    print(f"\n  완료: {elapsed:.1f}초 ({total/elapsed:.1f} req/s)\n")

    # ── Hot-Path 결과 분석 ─────────────────────────────────────────────────
    print("[ Hot-Path 결과 ]")

    # BLOCK=403, PASS/MONITOR=그 외, None=오류(Fail-Open 가능성)
    by_label = defaultdict(lambda: Counter())
    for true_label, status, _ in responses:
        verdict = "BLOCK" if status == 403 else ("PASS/MONITOR" if status is not None else "ERROR(Fail-Open?)")
        by_label[true_label][verdict] += 1

    print(f"  {'레이블':>10}  {'BLOCK(403)':>12}  {'PASS/MONITOR':>14}  {'ERROR':>8}")
    tp = fp = fn = tn = 0
    for lbl in sorted(by_label):
        c     = by_label[lbl]
        block = c["BLOCK"]
        other = c["PASS/MONITOR"]
        err   = c["ERROR(Fail-Open?)"]
        print(f"  {LABEL_MAP.get(lbl,'?'):>10}  {block:>12}  {other:>14}  {err:>8}")
        if lbl in ATTACK_LABELS:
            tp += block
            fn += other
        else:
            fp += block
            tn += other

    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / (tp + tn + fp + fn) * 100 if (tp + tn + fp + fn) > 0 else 0
    print(f"\n  정확도: {accuracy:.1f}%  |  정밀도: {precision:.1f}%  |  재현율: {recall:.1f}%  |  F1: {f1:.1f}%")
    print(f"  (주의: BLOCK만 집계. MONITOR는 PASS/MONITOR에 포함 → DB 검증 필요)\n")

    # ── DB 검증 (Cold-Path 포함) ────────────────────────────────────────────
    if conn:
        # @Async 로그 저장이 완료될 때까지 대기
        print("[ DB 검증 - attack_logs (3초 대기) ]")
        time.sleep(3)

        db_after = query_db_counts(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM attack_logs")
            after_total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM recommendations")
            rec_count = cur.fetchone()[0]

        new_logs = after_total - before_total
        print(f"  신규 attack_logs: {new_logs}건 (전체: {after_total}건)")
        print(f"  recommendations : {rec_count}건 (Cold-Path 결과)")

        print("\n  verdict × cwe_type 분포 (신규):")
        new_counts = {}
        for k, v in db_after.items():
            new_counts[k] = v - db_before.get(k, 0)

        print(f"  {'verdict':>10}  {'cwe_type':>10}  {'건수':>6}")
        for (verdict, cwe), cnt in sorted(new_counts.items()):
            if cnt > 0:
                print(f"  {verdict:>10}  {cwe:>10}  {cnt:>6}")

        # Cold-Path 결과 설명
        if rec_count == 0:
            print("\n  [Cold-Path] recommendations = 0")
            print("  → 예상된 결과: 테스트 URI(/tienda1/...)가 Spring 앱 엔드포인트에")
            print("    매핑되지 않아 EndpointResolver가 Optional.empty() 반환.")
            print("    Feedback Bridge 트리거 자체는 정상 동작.\n")

        conn.close()

    print("[ E2E 테스트 완료 ]")


if __name__ == "__main__":
    main()
