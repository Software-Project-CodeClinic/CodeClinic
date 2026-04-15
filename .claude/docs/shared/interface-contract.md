# 인터페이스 계약 (백엔드 ↔ AI)

> 이 파일은 **공동 소유**입니다. 변경 시 반드시 양쪽 합의 후 PR 진행.
> 변경 절차: `interface` 레이블 이슈 생성 → 양쪽 approve → merge → 각자 브랜치 동시 반영

---

## POST /predict

Spring `InferenceClient` → FastAPI 서버 호출.

### Request

```
POST http://localhost:8000/predict
Content-Type: application/json
```

```json
{
  "raw_input": "GET /api/users?id=1 OR 1=1 HTTP/1.1\r\nHost: example.com\r\n..."
}
```

| 필드 | 타입 | 설명 |
|------|------|------|
| `raw_input` | string | HTTP 요청 전체 문자열. **인코딩 정규화 없이** Raw 그대로 전달 |

### Response

```json
{
  "classificationScore": 0.92,
  "cweLabel": "CWE-89"
}
```

| 필드 | 타입 | 설명 |
|------|------|------|
| `classificationScore` | float | 0.0 (정상) ~ 1.0 (공격). DistilBERT argmax 출력의 score |
| `cweLabel` | string | 아래 레이블 중 하나 |

**cweLabel 허용값**

| 값 | 의미 |
|----|------|
| `"NORMAL"` | 정상 트래픽 |
| `"CWE-89"` | SQL Injection |
| `"CWE-79"` | Cross-Site Scripting |
| `"CWE-78"` | Command Injection |
| `"CWE-22"` | Path Traversal |

### 타임아웃 · 장애 처리

- 타임아웃: **50ms** (Spring `InferenceClient` 기준)
- 타임아웃 또는 서버 오류 시 → **Fail-Open**: `classificationScore=0.0`, `cweLabel="NORMAL"` 로 처리
- FastAPI 서버는 50ms 내 응답을 보장하도록 모델 로딩을 startup 시점에 완료해야 함

---

## FeatureVector (Spring 내부 DTO)

FastAPI에 전달하기 전 Spring이 구성하는 중간 객체.
`raw_input` 조합 방식을 양쪽이 알고 있어야 함.

```java
public record FeatureVector(
    String method,       // "GET", "POST" 등
    String uri,          // "/api/users?id=1 OR 1=1"
    String userAgent,
    String contentType,
    String rawBody,      // 정규화 없는 원본 body
    int    bodyLength
) {}
```

`raw_input` 조합 방식:
```
{method} {uri} HTTP/1.1\r\n
{헤더들}\r\n
\r\n
{rawBody}
```

---

## 버전 이력

| 날짜 | 변경 내용 | 관련 이슈 |
|------|-----------|-----------|
| 최초 작성 | `/predict` 엔드포인트 초안 | - |
