# WAF AI 모델 — 백엔드 연동 가이드

DistilBERT 기반 5-class HTTP 공격 분류 모델입니다.  
Spring Cloud Gateway의 Feature Extractor가 파싱한 요청을 받아 공격 유형과 신뢰도를 반환합니다.

---

## 모델 다운로드

학습 실험은 총 4개 케이스(A~D)로 진행됐으며, **Case C와 Case D** 두 가지 버전을 제공합니다.

| 케이스 | 특징 | 다운로드 |
|--------|------|----------|
| **Case C** | 탐지율 우선. CSIC2010 벤치마크 기준 DR 96.4%, FPR 0.54% | [Google Drive](https://drive.google.com/drive/folders/1jqbx1hZFOTB-gwlIYlu9Rg6bgZnNx_oZ?usp=drive_link) |
| **Case D** | 오탐율 우선. FPR 0.13% (Case C 대비 4배 감소), 외부 도메인 일반화 개선 | [Google Drive](https://drive.google.com/drive/folders/1GcuYr7x74C749QlLWVHb9DtBTVMWBC3g?usp=drive_link) |

### 케이스 선택 기준

```
Case C 선택 시: 탐지 누락(FN)을 최소화해야 할 때
Case D 선택 시: 정상 트래픽 오차단(FP)을 최소화해야 할 때 (권장)
```

> **현재 권장: Case D**  
> Case C는 학습 데이터의 정상 트래픽이 `/tienda1/...` 경로에 편중되어  
> 다른 도메인에서 정상 요청을 공격으로 잘못 분류하는 도메인 편향이 있습니다.  
> Case D는 합성 정상 데이터를 추가해 외부 도메인 오탐율을 대폭 개선했습니다.

### 성능 지표 (CSIC2010 held-out test, n=2,477)

| 지표 | Case C | Case D |
|------|--------|--------|
| Detection Rate (Recall) | **96.42%** | 94.97% |
| False Positive Rate | 0.54% | **0.13%** |
| Precision | 99.76% | 99.94% |
| F1 (Attack) | 0.9806 | 0.9739 |
| ROC-AUC | 0.9938 | 0.9924 |

### 폴더 구조 (다운로드 후)

```
case_c/ (또는 case_d/)
├── final/                  ← 추론에 필요한 파일 (이것만 사용)
│   ├── config.json
│   ├── model.safetensors   # 256MB
│   ├── tokenizer.json
│   └── tokenizer_config.json
├── checkpoint-*/           ← 학습 중간 체크포인트 (추론 불필요)
└── eval_csic/              ← 평가 결과 로그
```

서버 실행 시 **`final/` 디렉토리 경로**를 모델 경로로 지정하세요.

---

## 모델 입력 형식

### 핵심 규칙

모델은 다음 형식의 **단일 텍스트 문자열**을 입력으로 받습니다.

```
{METHOD} {URI}
{BODY}
```

- `{METHOD}`: HTTP 메서드 대문자 (`GET`, `POST`, ...)
- `{URI}`: 쿼리스트링 포함 전체 URI
- `{BODY}`: POST body (없으면 생략, 줄바꿈도 생략)
- 구분자: `\n` (개행 1개)
- **인코딩 정규화 금지**: URL 인코딩(`%2F`, `%3D` 등)을 디코딩하지 말 것. 모델이 인코딩 패턴 자체를 공격 지표로 학습했습니다.

### GET 요청 예시

```
GET /products?id=1 OR 1=1--&sort=name
```

```
GET /search?q=<script>alert(1)</script>&page=1
```

```
GET /download?file=../../etc/passwd&token=abc
```

### POST 요청 예시

```
POST /login
username=admin' OR '1'='1--&password=test
```

```
POST /comment
content=<img src=x onerror=alert(1)>&post_id=5
```

```
POST /system/run
cmd=ls; cat /etc/passwd&timeout=30
```

### 텍스트 구성 코드 (Python)

```python
def build_input_text(method: str, uri: str, body: str = '') -> str:
    text = f"{method.upper()} {uri}"
    if body:
        text += f"\n{body}"
    return text
```

이 함수는 `src/predict.py`의 `WAFPredictor._build_text()`와 동일한 로직입니다.

---

## FastAPI 서버 연동

### `/predict` 엔드포인트 계약

백엔드(Spring)에서 아래 형식으로 POST 요청을 보냅니다.

**Request**

```http
POST http://localhost:8000/predict
Content-Type: application/json

{
  "raw_input": "GET /search?q=1 OR 1=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
}
```

> `raw_input`은 Spring Feature Extractor가 조합한 HTTP 전문(메서드·헤더·바디 포함)입니다.  
> FastAPI 서버 내부에서 method, uri, body를 파싱한 뒤 위의 입력 형식으로 변환합니다.

**Response**

```json
{
  "classificationScore": 0.9742,
  "cweLabel": "CWE-89"
}
```

| 필드 | 타입 | 설명 |
|------|------|------|
| `classificationScore` | float | 예측 신뢰도 (0.0 ~ 1.0) |
| `cweLabel` | string | 아래 허용값 중 하나 |

**cweLabel 허용값**

| 값 | 공격 유형 | 내부 label_id |
|----|-----------|---------------|
| `"NORMAL"` | 정상 트래픽 | 0 |
| `"CWE-89"` | SQL Injection | 1 |
| `"CWE-79"` | Cross-Site Scripting | 2 |
| `"CWE-78"` | OS Command Injection | 3 |
| `"CWE-22"` | Path Traversal | 4 |

**타임아웃 및 장애 처리**

- Spring `InferenceClient` 타임아웃: **50ms**
- 타임아웃 또는 서버 오류 시 → **Fail-Open** (`classificationScore=0.0`, `cweLabel="NORMAL"`)
- FastAPI 서버는 모델을 **startup 시점에 미리 로드**해 요청당 지연을 최소화해야 합니다.

### FastAPI 서버 구현 예시

```python
# ai-server/main.py
from fastapi import FastAPI
from pydantic import BaseModel
from src.predict import WAFPredictor

app = FastAPI()
predictor = WAFPredictor("./models/case_d/final")  # 서버 시작 시 1회 로드

CWE_MAP = {
    "Normal": "NORMAL",
    "SQLi":   "CWE-89",
    "XSS":    "CWE-79",
    "CMDi":   "CWE-78",
    "Path":   "CWE-22",
}

class PredictRequest(BaseModel):
    raw_input: str

@app.post("/predict")
def predict(req: PredictRequest):
    # raw_input에서 method, uri, body 파싱
    method, uri, body = parse_raw_input(req.raw_input)
    result = predictor.predict(method=method, uri=uri, body=body)
    return {
        "classificationScore": result["confidence"],
        "cweLabel": CWE_MAP[result["label"]],
    }

def parse_raw_input(raw: str) -> tuple[str, str, str]:
    """HTTP 전문에서 method, uri, body 추출"""
    lines = raw.split("\r\n")
    request_line = lines[0].split(" ")
    method = request_line[0]
    uri = request_line[1] if len(request_line) > 1 else "/"
    # 헤더와 바디 분리 (\r\n\r\n 기준)
    if "\r\n\r\n" in raw:
        body = raw.split("\r\n\r\n", 1)[1]
    else:
        body = ""
    return method, uri, body
```

### 모델 직접 사용 (추론 테스트)

```python
from src.predict import WAFPredictor

predictor = WAFPredictor("./models/case_d/final")

# 단건 추론
result = predictor.predict(
    method="GET",
    uri="/search?q=1 OR 1=1--",
    body=""
)
# {'label': 'SQLi', 'label_id': 1, 'confidence': 0.97, 'scores': {...}}

# 배치 추론
results = predictor.predict_batch([
    {"method": "GET",  "uri": "/products?id=1",         "body": ""},
    {"method": "POST", "uri": "/login",                  "body": "username=admin'--"},
    {"method": "GET",  "uri": "/download?file=../../etc/passwd", "body": ""},
])
```

---

## 의존성

```
torch>=2.0
transformers>=4.30
fastapi
uvicorn
```

---

## 참고

- 모델 학습 실험 상세: `waf_model/EXPERIMENT_REPORT.md`, `CASE_D_REPORT.md`
- 인터페이스 계약 (변경 시 양쪽 합의 필요): `.claude/docs/shared/interface-contract.md`
- 담당: 영현 (`feat/ai/*`)
