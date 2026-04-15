# CodeClinic — Claude Context

CodeClinic (Spring Cloud Gateway + DistilBERT + Feedback Bridge)

## 역할 분담

| 담당자 | 역할 | 브랜치 prefix | 디렉토리 |
|--------|------|---------------|----------|
| 태현 | 백엔드 / 인프라 | `feat/backend/*` | `backend/` |
| 영현 | AI / ML | `feat/ai/*` | `ai-server/` |

## 브랜치 전략

Trunk-Based Development — 브랜치 수명 최대 1~2일, main에 자주 merge.  
자세한 규칙 → [.claude/docs/shared/collaboration.md](.claude/docs/shared/collaboration.md)

## 문서 라우팅

| 목적 | 문서 |
|------|------|
| 전체 아키텍처 · 설계 결정 | [.claude/docs/shared/architecture.md](.claude/docs/shared/architecture.md) |
| **인터페이스 계약** (백엔드↔AI) | [.claude/docs/shared/interface-contract.md](.claude/docs/shared/interface-contract.md) |
| 협업 규칙 · 커밋 컨벤션 | [.claude/docs/shared/collaboration.md](.claude/docs/shared/collaboration.md) |
| 주차별 구현 계획 | [.claude/docs/shared/implementation-plan.md](.claude/docs/shared/implementation-plan.md) |
| Post-MVP 로드맵 | [.claude/docs/shared/post-mvp.md](.claude/docs/shared/post-mvp.md) |
| Hot Path 상세 | [.claude/docs/backend/hot-path.md](.claude/docs/backend/hot-path.md) |
| Feedback Bridge 상세 | [.claude/docs/backend/cold-path.md](.claude/docs/backend/cold-path.md) |
| 인프라 / Docker / DB | [.claude/docs/backend/infra.md](.claude/docs/backend/infra.md) |
| AI 모델 · FastAPI 서버 | [.claude/docs/ai/model.md](.claude/docs/ai/model.md) |
| 데이터셋 · 실험 결과 | [.claude/docs/ai/dataset.md](.claude/docs/ai/dataset.md) |

## 핵심 설계 결정 (요약)

- **Fail-Open**: AI 서버 장애 시 50ms 타임아웃 후 무조건 PASS
- **Raw Input**: 인코딩 정규화 없이 모델에 전달 (모델이 인코딩 패턴까지 학습)
- **Hot/Cold 분리**: 탐지·판정(동기) vs Feedback Bridge(비동기, @TransactionalEventListener)
- **CWE 레이블**: 모델 argmax 출력 그대로 사용 (별도 분류 로직 없음)
