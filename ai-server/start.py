#!/usr/bin/env python3
"""
WAF AI 서버 기동 스크립트

사용법:
  python ai-server/start.py                    # case_f (기본)
  python ai-server/start.py --model case_g
  python ai-server/start.py --model case_g --port 9001
  python ai-server/start.py --list             # 사용 가능한 모델 목록
"""
import argparse
import os
import sys

import uvicorn

# 이 파일 기준으로 models 디렉토리 탐색
_HERE = os.path.dirname(os.path.abspath(__file__))


def _available_models() -> dict[str, str]:
    """models/ 하위에서 final/ 디렉토리를 가진 케이스를 자동 탐색."""
    models_dir = os.path.join(_HERE, "models")
    result = {}
    if not os.path.isdir(models_dir):
        return result
    for name in sorted(os.listdir(models_dir)):
        final_path = os.path.join(models_dir, name, "final")
        if os.path.isdir(final_path):
            result[name] = os.path.join("models", name, "final")
    return result


def main():
    available = _available_models()
    if not available:
        sys.exit("모델을 찾을 수 없습니다. ai-server/models/<name>/final/ 구조를 확인하세요.")

    default_model = "case_f" if "case_f" in available else next(iter(available))

    parser = argparse.ArgumentParser(description="WAF AI 서버 기동")
    parser.add_argument(
        "--model", default=default_model, choices=list(available),
        help=f"사용할 모델 (기본: {default_model})",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--list", action="store_true", help="사용 가능한 모델 목록 출력 후 종료")
    args = parser.parse_args()

    if args.list:
        print("사용 가능한 모델:")
        for name, path in available.items():
            marker = " ← 기본" if name == default_model else ""
            print(f"  {name:<12}  {path}{marker}")
        return

    model_path = available[args.model]
    os.environ["MODEL_PATH"] = model_path
    print(f"모델: {args.model}  ({model_path})")
    print(f"주소: http://{args.host}:{args.port}")

    os.chdir(_HERE)
    uvicorn.run("main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
