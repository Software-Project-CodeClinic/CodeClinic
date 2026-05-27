#!/usr/bin/env python3
"""
AI 모델 정확도 평가 스크립트 (Spring/Docker 불필요)

사전 조건:
  cd ai-server && uvicorn main:app --host 0.0.0.0 --port 8000

사용법:
  python scripts/eval_ai.py                   # test_with_headers.csv, 전체, URI 디코딩 on
  python scripts/eval_ai.py --limit 200       # 처음 200건
  python scripts/eval_ai.py --csv test.csv    # URI-only CSV (Model F 비교용)
  python scripts/eval_ai.py --no-decode-uri   # 디코딩 비활성화
"""
import argparse
import csv
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import unquote_plus, urlparse

try:
    import requests
except ImportError:
    sys.exit("pip install requests 필요")

LABEL_MAP = {0: "NORMAL", 1: "CWE-89", 2: "CWE-79", 3: "CWE-78", 4: "CWE-22"}
# WAF 분류: 0=NORMAL, else=ATTACK
ATTACK_LABELS = {1, 2, 3, 4}

def build_raw_input(text: str, decode_uri: bool = True) -> str:
    """Full HTTP Request 포맷 (Model G용).

    test_with_headers.csv 첫 줄의 절대 URL을 상대 경로로 정규화.
    원본 헤더와 body는 그대로 보존.
    """
    text = text.strip()
    sep = "\r\n" if "\r\n" in text else "\n"
    first_line, _, remainder = text.partition(sep)

    tokens = first_line.split(" ", 2)
    method  = tokens[0] if tokens else "GET"
    raw_url = tokens[1] if len(tokens) >= 2 else "/"
    proto   = tokens[2] if len(tokens) >= 3 else "HTTP/1.1"

    if raw_url.startswith("http"):
        p = urlparse(raw_url)
        uri = p.path + (("?" + p.query) if p.query else "")
    else:
        uri = raw_url.split(" ")[0]

    if decode_uri:
        uri = unquote_plus(uri)

    first_line_new = f"{method} {uri} {proto}"
    return (first_line_new + sep + remainder) if remainder else first_line_new


def predict(session, url: str, raw_input: str) -> dict | None:
    try:
        r = session.post(
            f"{url}/predict",
            json={"raw_input": raw_input},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"\n  [WARN] /predict 오류: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",        default="test_with_headers.csv")
    parser.add_argument("--url",        default="http://localhost:8000")
    parser.add_argument("--limit",      type=int, default=None)
    parser.add_argument("--decode-uri", default=True,
                        action=argparse.BooleanOptionalAction,
                        help="URI 디코딩 (기본: on). --no-decode-uri로 비활성화.")
    args = parser.parse_args()

    # AI 서버 health check
    try:
        r = requests.get(f"{args.url}/health", timeout=3)
        r.raise_for_status()
        info = r.json()
        model_name = info.get("model", "unknown")
        print(f"AI 서버 연결 확인: {args.url}  |  모델: {model_name}")
    except Exception:
        sys.exit(f"AI 서버({args.url})에 연결할 수 없습니다. start.py를 먼저 실행하세요.")

    # 데이터 로딩
    with open(args.csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if args.limit:
        rows = rows[:args.limit]
    decode_uri = args.decode_uri
    mode_label = "URI 디코딩 O" if decode_uri else "URI 디코딩 X (원본)"
    print(f"테스트 데이터: {args.csv} ({len(rows)}건)  |  모드: {mode_label}\n")

    # 예측 실행
    session   = requests.Session()
    correct   = 0
    errors    = 0
    confusion = defaultdict(Counter)   # confusion[true][pred]
    latencies = []

    for i, row in enumerate(rows, 1):
        true_label = int(row["label"])
        raw_input  = build_raw_input(row["text"], decode_uri=decode_uri)

        t0     = time.time()
        result = predict(session, args.url, raw_input)
        latencies.append((time.time() - t0) * 1000)

        if result is None:
            errors += 1
            continue

        # cweLabel → int 역매핑
        cwe_to_int = {v: k for k, v in LABEL_MAP.items()}
        pred_label = cwe_to_int.get(result["cweLabel"], -1)

        confusion[true_label][pred_label] += 1
        if true_label == pred_label:
            correct += 1

        # 진행 표시
        if i % 100 == 0 or i == len(rows):
            pct = correct / (i - errors) * 100
            print(f"  [{i:>4}/{len(rows)}] 정확도 {pct:.1f}%  avg {sum(latencies)/len(latencies):.1f}ms")

    # ── 결과 출력 ──────────────────────────────────────────────────────────
    total  = len(rows) - errors
    acc    = correct / total * 100 if total else 0
    avg_ms = sum(latencies) / len(latencies) if latencies else 0

    print("\n" + "=" * 60)
    print(f"  정확도: {correct}/{total} ({acc:.2f}%)")
    print(f"  평균 추론 시간: {avg_ms:.1f}ms  |  오류: {errors}건")

    # 혼동 행렬
    print("\n  혼동 행렬 (행=실제, 열=예측)")
    all_labels = sorted(set(confusion.keys()) | {p for v in confusion.values() for p in v})
    header = "         " + "".join(f"{LABEL_MAP.get(l,'?'):>9}" for l in all_labels)
    print(header)
    for true in all_labels:
        row_str = f"  {LABEL_MAP.get(true,'?'):>7}"
        for pred in all_labels:
            row_str += f"{confusion[true][pred]:>9}"
        print(row_str)

    # 클래스별 정밀도/재현율
    print("\n  클래스별 지표")
    print(f"  {'레이블':>10}  {'재현율(Recall)':>15}  {'정밀도(Precision)':>18}")
    for label in all_labels:
        tp = confusion[label][label]
        fn = sum(confusion[label][p] for p in all_labels if p != label)
        fp = sum(confusion[t][label] for t in all_labels if t != label)
        recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        print(f"  {LABEL_MAP.get(label,'?'):>10}  {recall:>14.1f}%  {precision:>17.1f}%")

    print("=" * 60)


if __name__ == "__main__":
    main()
