#!/usr/bin/env bash
# scripts/install-hooks.sh
# clone 후 1회 실행: git hooks 설치
# 사용법: bash scripts/install-hooks.sh

set -e

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
  echo "❌  git 저장소 루트를 찾을 수 없습니다. 프로젝트 루트에서 실행해 주세요."
  exit 1
fi

HOOKS_DIR="$REPO_ROOT/.githooks"
GIT_HOOKS_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_DIR" ]; then
  echo "❌  .githooks 디렉토리가 없습니다: $HOOKS_DIR"
  exit 1
fi

echo ""
echo "🔧  CodeClinic — Git Hooks 설치"
echo ""

# git config로 hooksPath 설정 (심볼릭 링크 없이 동작)
git config core.hooksPath .githooks
echo "✅  core.hooksPath = .githooks"

# 실행 권한 확인 및 부여
for hook in "$HOOKS_DIR"/*; do
  if [ -f "$hook" ]; then
    chmod +x "$hook"
    echo "✅  chmod +x $(basename $hook)"
  fi
done

echo ""
echo "🎉  설치 완료!"
echo ""
echo "    적용된 hooks:"
echo "    • commit-msg       : 커밋 메시지 형식 검증"
echo "    • prepare-commit-msg: 브랜치명 기반 메시지 템플릿 자동 삽입"
echo "    • pre-push         : main 직접 push 차단 + 브랜치 네이밍 검증"
echo ""
