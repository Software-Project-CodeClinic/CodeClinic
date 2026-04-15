# 전체 아키텍처

## 시스템 흐름

```
[Client]
   │ HTTP 요청
   ▼
[Traffic Gateway]  ← Spring Cloud Gateway, GlobalFilter (order=-100)
   │
   ▼
[Feature Extractor] ← URI / Method / Header / Body 파싱 (Raw Input, 정규화 없음)
   │
   ▼
[AI Inference Server] ← FastAPI + DistilBERT (POST /predict, 50ms timeout)
   │  classificationScore + cweLabel
   ▼
[Decision Engine] ← BLOCK / MONITOR / PASS (임계값: yml 외부화)
   │
   ├── PASS  → upstream 프록시
   ├── BLOCK → 403 즉시 반환
   └── MONITOR/BLOCK
          │
          ▼
     [Attack Log Service] ← @Async, TimescaleDB hypertable
          │ @TransactionalEventListener (커밋 후)
          ▼
     [Feedback Bridge] ← Cold Path (응답과 완전 분리)
          │
          ├── EndpointResolver  → URI+Method → Spring 핸들러
          ├── SourceLocator     → 핸들러 → .java 파일 경로
          ├── SemgrepRunner     → CWE 규칙셋으로 취약점 탐지
          └── RecommendationBuilder → 권고 템플릿 → DB 저장
```

## Hot Path vs Cold Path

| | Hot Path | Cold Path |
|---|---|---|
| 포함 레이어 | Gateway → FeatureExtractor → AI → DecisionEngine | AttackLogService → Feedback Bridge |
| 실행 방식 | 동기 (Reactive Mono 체인) | 비동기 (@Async + @TransactionalEventListener) |
| 응답 영향 | 직접 영향 | 없음 (완전 분리) |
| 목적 | 탐지 · 차단 | 소스코드 역추적 · 권고 |

## 핵심 설계 결정

| 결정 | 내용 | 이유 |
|------|------|------|
| Fail-Open | AI 장애 시 무조건 PASS | 보안보다 서비스 가용성 우선 |
| Raw Input 전달 | 인코딩 정규화 없이 모델에 전달 | 모델이 인코딩 패턴까지 학습 (논문 기준) |
| DistilBERT argmax | CWE 레이블을 모델 출력에서 직접 사용 | 별도 CweClassifier 불필요 |
| TimescaleDB | 공격 로그 저장소 | 시계열 범위 쿼리 성능 (hypertable) |
| Semgrep CLI | ProcessBuilder 호출 | AST 기반 정확한 취약점 탐지 |

## 인터페이스 계약 (백엔드 ↔ AI)

**Request**
```json
POST /predict
{ "raw_input": "GET /api/users?id=1 OR 1=1 HTTP/1.1\nHost: ..." }
```

**Response**
```json
{ "classificationScore": 0.92, "cweLabel": "CWE-89" }
```

- `classificationScore`: 0.0 (정상) ~ 1.0 (공격)
- `cweLabel`: `"CWE-89"` | `"CWE-79"` | `"CWE-78"` | `"CWE-22"` | `"NORMAL"`
- 타임아웃: 50ms → 초과 시 `{ "classificationScore": 0.0, "cweLabel": "NORMAL" }` 반환 (Fail-Open)
