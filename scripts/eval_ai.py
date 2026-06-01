#!/usr/bin/env python3
"""
AI 모델 정확도 평가 스크립트 (Spring/Docker 불필요)

사전 조건:
  cd ai-server && uvicorn main:app --host 0.0.0.0 --port 8000

사용법:
  python scripts/eval_ai.py                          # case_g, full 모드, 디코딩 on
  python scripts/eval_ai.py --model case_f           # case_f 모델로 평가
  python scripts/eval_ai.py --mode uri-only          # 헤더 제거, 첫 줄만
  python scripts/eval_ai.py --limit 200              # 처음 200건
  python scripts/eval_ai.py --no-decode-uri          # 디코딩 비활성화
"""
import argparse
import csv
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import unquote, urlparse

try:
    import requests
except ImportError:
    sys.exit("pip install requests 필요")

LABEL_MAP = {0: "NORMAL", 1: "CWE-89", 2: "CWE-79", 3: "CWE-78", 4: "CWE-22"}
# WAF 분류: 0=NORMAL, else=ATTACK
ATTACK_LABELS = {1, 2, 3, 4}

def _parse_first_line(text: str) -> tuple[str, str, str, str, str]:
    """첫 줄에서 method, uri, proto를 추출하고 sep·remainder를 반환."""
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
    return method, uri, proto, sep, remainder


def build_raw_input(text: str, decode_uri: bool = True, mode: str = "full") -> str:
    method, uri, proto, sep, remainder = _parse_first_line(text)
    if decode_uri:
        uri = unquote(uri)
    first_line_new = f"{method} {uri} {proto}"
    if mode == "uri-only":
        return first_line_new + "\r\n"
    return (first_line_new + sep + remainder) if remainder else first_line_new


def _start_ai_server(model: str, url: str) -> None:
    port = urlparse(url).port or 8000
    ai_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai-server")
    env = {**os.environ, "MODEL_PATH": os.path.join("models", model, "final")}
    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(port)],
        cwd=ai_dir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"  AI 서버 기동 중 (모델: {model})", end="", flush=True)
    for _ in range(20):
        time.sleep(1)
        print(".", end="", flush=True)
        try:
            if requests.get(f"{url}/health", timeout=1).ok:
                print()
                return
        except Exception:
            pass
    print()
    sys.exit(f"AI 서버 기동 실패 ({model})")


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
    parser.add_argument("--mode", default="full", choices=["full", "uri-only"],
                        help="full: 헤더+body 포함 (기본) | uri-only: 첫 줄만")
    parser.add_argument("--model", default="case_g",
                        help="평가할 모델 (기본: case_g). 서버 미기동 시 자동 시작.")
    args = parser.parse_args()

    # AI 서버 health check (모델 불일치 시 오류, 미기동 시 자동 시작)
    try:
        r = requests.get(f"{args.url}/health", timeout=3)
        r.raise_for_status()
        running_model = r.json().get("model", "unknown")
        if running_model != args.model:
            sys.exit(
                f"서버 모델 불일치: 실행 중='{running_model}', 요청='{args.model}'\n"
                f"  서버를 재시작하거나 --model {running_model} 옵션을 사용하세요."
            )
        print(f"AI 서버 연결 확인: {args.url}  |  모델: {running_model}")
    except requests.exceptions.ConnectionError:
        _start_ai_server(args.model, args.url)
        print(f"AI 서버 자동 시작 완료: {args.url}  |  모델: {args.model}")
    except SystemExit:
        raise
    except Exception:
        sys.exit(f"AI 서버({args.url})에 연결할 수 없습니다.")

    # 데이터 로딩
    with open(args.csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if args.limit:
        rows = rows[:args.limit]
    decode_uri = args.decode_uri
    decode_label = "URI 디코딩 O" if decode_uri else "URI 디코딩 X"
    print(f"테스트 데이터: {args.csv} ({len(rows)}건)  |  입력 모드: {args.mode}  |  {decode_label}\n")

    # 예측 실행
    session   = requests.Session()
    correct   = 0
    errors    = 0
    confusion = defaultdict(Counter)   # confusion[true][pred]
    latencies = []

    for i, row in enumerate(rows, 1):
        true_label = int(row["label"])
        raw_input  = build_raw_input(row["text"], decode_uri=decode_uri, mode=args.mode)

        t0     = time.time()
        result = predict(session, args.url, raw_input)
        latencies.append((time.time() - t0) * 1000)

        if result is None:
            errors += 1
            continue

        # cweLabel → int 역매핑
        cwe_to_int = {v: k for k, v in LABEL_MAP.items()}
        pred_label = cwe_to_int.get(result.get("cweLabel"), -1)

        confusion[true_label][pred_label] += 1
        if true_label == pred_label:
            correct += 1

        # 진행 표시
        if i % 100 == 0 or i == len(rows):
            seen = i - errors
            pct = correct / seen * 100 if seen > 0 else 0.0
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
