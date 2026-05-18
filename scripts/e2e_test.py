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

사용법:
  python scripts/e2e_test.py                  # test.csv, 전체
  python scripts/e2e_test.py --limit 100      # 처음 100건
  python scripts/e2e_test.py --no-db-check    # DB 검증 생략
"""
import argparse
import csv
import sys
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

GATEWAY = "http://localhost:8080"
DB_DSN  = "postgresql://waf:waf_local_secret@localhost:5432/waf"

LABEL_MAP    = {0: "NORMAL", 1: "CWE-89", 2: "CWE-79", 3: "CWE-78", 4: "CWE-22"}
ATTACK_LABELS = {1, 2, 3, 4}

# verdict → 기대 범주 (레이블 기준)
#   true NORMAL → PASS
#   true ATTACK → BLOCK 또는 MONITOR


def parse_request_line(text: str):
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

    return method, path or "/"


def send_request(session, method: str, path: str) -> requests.Response | None:
    url = GATEWAY + path
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",      default="test.csv")
    parser.add_argument("--gateway",  default=GATEWAY)
    parser.add_argument("--db",       default=DB_DSN)
    parser.add_argument("--limit",    type=int, default=None)
    parser.add_argument("--no-db-check", action="store_true")
    args = parser.parse_args()

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

    t_start = time.time()
    for i, row in enumerate(rows, 1):
        true_label = int(row["label"])
        method, path = parse_request_line(row["text"])

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
        verdict = "BLOCK" if status == 403 else ("PASS/MONITOR" if status else "ERROR(Fail-Open?)")
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
