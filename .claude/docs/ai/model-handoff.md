# AI 모델 인수인계 가이드 (백엔드 개발자용)

> **대상:** 백엔드 담당  
> **작성:** AI/ML 담당  
> **모델:** DistilBERT 기반 5클래스 WAF HTTP 요청 분류기 — Case F (최종 채택)

---

## 1. 모델 개요

HTTP 요청 문자열을 입력받아 **공격 유형을 5개 클래스로 분류**하는 모델이다.

| 항목 | 값 |
|------|-----|
| 베이스 모델 | `distilbert-base-uncased` (Hugging Face) |
| 아키텍처 | DistilBertForSequenceClassification (6-layer Transformer) |
| 분류 클래스 수 | 5클래스 |
| 최대 입력 토큰 | 256 tokens |
| 출력 | 각 클래스 확률 → argmax로 레이블 결정 |
| 학습 환경 | RTX 3060 12GB, PyTorch 2.5.1 |
| 학습 소요 시간 | ~20분 (9 epochs, early stopping) |

**클래스 정의**

| label_id | label (내부) | cweLabel (API 출력) | 의미 |
|----------|------------|-------------------|------|
| 0 | Normal | `"NORMAL"` | 정상 트래픽 |
| 1 | SQLi | `"CWE-89"` | SQL Injection |
| 2 | XSS | `"CWE-79"` | Cross-Site Scripting |
| 3 | CMDi | `"CWE-78"` | Command Injection |
| 4 | Path | `"CWE-22"` | Path Traversal |

---

## 2. 모델 파일 구조

```text
waf_model/
├── models/
│   └── case_f/
│       └── final/              ← ★ 배포용 디렉토리 (이 4개 파일만 사용)
│           ├── config.json         모델 아키텍처 설정
│           ├── model.safetensors   학습된 가중치 (DistilBERT fine-tuned)
│           ├── tokenizer.json      WordPiece 어휘사전 + 토크나이저 설정
│           └── tokenizer_config.json  토크나이저 메타데이터
├── src/
│   ├── predict.py              추론 API (WAFPredictor 클래스)
│   ├── preprocess.py           텍스트 전처리 (NFKD 정규화 포함)
│   ├── train_multiclass.py     학습 스크립트
│   ├── evaluate.py             CSIC2010 평가 스크립트
│   ├── eval_ood.py             OOD(VulnBank) 평가 스크립트
│   ├── merge_datasets.py       Case별 학습 데이터 조합 스크립트
│   ├── build_csic.py           CSIC2010 파싱 + NFKD 정규화
│   └── build_ood_vulnbank.py   VulnBank 데이터 파싱
└── data/
    ├── case_f/                 Case F 학습/검증/테스트 CSV
    │   ├── train.csv           (19,965건)
    │   ├── val.csv             (4,212건)
    │   └── test.csv            (2,477건)
    └── ood_vulnbank/
        ├── eval.csv            OOD 공정 평가셋 (held-out benign 2,211 + attack 946)
        └── test.csv            OOD 전체 비교용 (benign 3,211 + attack 946)
```

**배포 시 필요한 파일**: `models/case_f/final/` 디렉토리 전체 (4개 파일)

### 각 파일 역할 상세

| 파일 | 역할 | 백엔드와의 관련성 |
|------|------|----------------|
| `config.json` | 모델 구조 정의 (레이어 수, hidden_dim, 클래스 수 등) | transformers 라이브러리가 자동 읽음 — 직접 수정 불가 |
| `model.safetensors` | 학습된 가중치 파라미터 (~260MB) | 실제 분류 능력이 담긴 파일 |
| `tokenizer.json` | 30,522개 WordPiece 어휘 + 토크나이징 규칙 | HTTP 요청 문자열 → 토큰 ID 변환 |
| `tokenizer_config.json` | 토크나이저 메타데이터 (소문자 변환 등) | `do_lower_case: true` — 대소문자 구분 없음 |

---

## 3. 학습 데이터 상세

Case F는 세 가지 데이터 소스를 결합해 학습했다.

### 3-1. 데이터 소스

| 소스 | 역할 | 건수 (Train) | 특성 |
|------|------|------------|------|
| **CSIC2010** | Normal + 공격(SQLi/XSS 등) | Normal 3,420 / Attack 다수 | 실제 e-commerce 트래픽. 스페인어 특수문자 포함 |
| **SecLists / PayloadsAllTheThings** | 공격 5클래스 페이로드 | SQLi 6,000 / XSS 3,343 / CMDi 3,000 / Path 3,053 | 알려진 공격 패턴 라이브러리에서 추출한 페이로드. 8종 HTTP 요청 템플릿에 삽입 |
| **VulnBank benign** | Normal (OOD 도메인) | 1,000 | 실제 banking 앱(`/vulnbank/`) 정상 트래픽. OOD FPR 해소 목적으로 추가 |
| **합성 Normal** | Normal 다양성 보강 | 144 | `/search`, `/login`, `/tienda1/` 경로 정상 요청 직접 작성 |

**합계: Train 19,965건 / Val 4,212건 / Test 2,477건**

### 3-2. 데이터 전처리 파이프라인

```text
원본 데이터 (CSIC2010 txt, SecLists txt, VulnBank csv)
       ↓
① NFKD 정규화  — é→e, ó→o, ñ→n (비ASCII 문자를 ASCII 기저 문자로 변환)
② ASCII 필터링 — 기저 문자 이외 결합 문자 제거
③ HTTP 요청 조립 — "{METHOD} {URI}\n{BODY}" 형태로 정규화
④ 텍스트 정리  — 연속 공백 단일화, 최대 1024자 클리핑
       ↓
CSV (text, label) 형태로 저장
```

**중요**: NFKD 정규화는 학습 데이터 생성 시에만 적용된다. **FastAPI 서버가 추론 전에 동일한 정규화를 적용해야 한다** (학습-추론 일관성 보장). `preprocess.py`의 `clean_text()` 함수를 그대로 사용할 것.

### 3-3. 클래스 가중치 (불균형 보정)

학습 시 역빈도 가중치를 CrossEntropy 손실에 적용했다.

| 클래스 | Train 건수 | 가중치 |
|--------|----------|--------|
| Normal | 4,569 | 0.874 |
| SQLi | 6,000 | 0.665 |
| XSS | 3,343 | 1.194 |
| CMDi | 3,000 | 1.331 |
| Path | 3,053 | 1.308 |

> Normal 4,569 = CSIC2010 3,420 + 합성 144건 + VulnBank benign 1,000건 + merge 중복 제거 5건

---

## 4. 입력 포맷 (백엔드 → AI 서버)

백엔드(Spring)는 `POST /predict`로 HTTP 요청 문자열을 전송한다.

### 4-1. API 요청

```http
POST http://localhost:8000/predict
Content-Type: application/json
```

```json
{
  "raw_input": "GET /api/users?id=1 OR 1=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
}
```

| 필드 | 타입 | 설명 |
|------|------|------|
| `raw_input` | string | **인코딩 정규화 없이** Spring이 파싱한 원본 HTTP 요청 문자열 |

### 4-2. `raw_input` 조합 방법

Spring의 `FeatureVector` 기준:

```java
// FeatureVector 구성
String rawInput = method + " " + uri + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + (userAgent != null ? "User-Agent: " + userAgent + "\r\n" : "")
                + (contentType != null ? "Content-Type: " + contentType + "\r\n" : "")
                + "\r\n"
                + (rawBody != null ? rawBody : "");
```

**실제 학습 데이터의 텍스트 포맷:**
```text
GET /products?id=1 OR 1=1--&sort=name
```
```text
POST /login
username=admin' OR '1'='1&password=test
```

> 모델은 `{METHOD} {URI}\n{BODY}` 형태로 학습되었다. 헤더는 학습에 포함되지 않았으므로, `raw_input`에 헤더를 포함해도 256토큰 이내에서 처리되나, **탐지에 기여하는 정보는 Method, URI, Body**다.

### 4-3. AI 서버 내부 처리 

```python
# AI 서버가 raw_input을 받아 처리하는 흐름
def preprocess(raw_input: str) -> str:
    # 1. NFKD 정규화 (학습 데이터와 동일하게)
    text = unicodedata.normalize('NFKD', raw_input).encode('ascii', errors='ignore').decode('ascii')
    # 2. 공백 정리
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:1024]

# 토크나이저 → 모델 추론
inputs = tokenizer(text, truncation=True, padding='max_length',
                   max_length=256, return_tensors='pt')
logits = model(**inputs).logits
probs  = torch.softmax(logits, dim=-1)
label_id = probs.argmax().item()
```

---

## 5. 출력 포맷 (AI 서버 → 백엔드)

```json
{
  "classificationScore": 0.97,
  "cweLabel": "CWE-89"
}
```

| 필드 | 타입 | 범위 | 설명 |
|------|------|------|------|
| `classificationScore` | float | 0.0 ~ 1.0 | 예측 클래스의 softmax 확률. 높을수록 해당 클래스 신뢰도 높음 |
| `cweLabel` | string | 아래 5가지 | argmax 클래스 |

**cweLabel 허용값**

| 값 | 공격 유형 | 예시 페이로드 |
|----|---------|-------------|
| `"NORMAL"` | 정상 트래픽 | `GET /api/users?id=1` |
| `"CWE-89"` | SQL Injection | `GET /api/users?id=1 OR 1=1--` |
| `"CWE-79"` | Cross-Site Scripting | `GET /search?q=<script>alert(1)</script>` |
| `"CWE-78"` | Command Injection | `GET /ping?host=127.0.0.1; cat /etc/passwd` |
| `"CWE-22"` | Path Traversal | `GET /download?file=../../etc/passwd` |

### 판정 기준 (Decision Engine)

`cweLabel != "NORMAL"` 이면 공격으로 판정한다. `classificationScore`는 임계값 기반 세부 제어에 사용할 수 있다.

```text
classificationScore = 0.97, cweLabel = "CWE-89"  → BLOCK (SQLi 공격, 신뢰도 97%)
classificationScore = 0.52, cweLabel = "CWE-89"  → MONITOR or BLOCK (경계값 — yml 임계값 설정)
classificationScore = 0.98, cweLabel = "NORMAL"  → PASS (정상, 신뢰도 98%)
```

> **임계값 권고**: 기본값(0.5)으로 CSIC FPR 0.27% / Detection Rate 97.28% 달성. 임계값 0.111로 낮추면 DR 97.57%이나 FPR 0.54%로 증가. `application.yml`에서 외부화 권장.

### Fail-Open 처리

AI 서버 장애 또는 **50ms 타임아웃** 시:

```json
{ "classificationScore": 0.0, "cweLabel": "NORMAL" }
```

→ `PASS`로 처리 (서비스 가용성 우선)

---

## 6. 성능 지표 요약

### CSIC2010 평가 (in-domain)

| 지표 | 값 |
|------|-----|
| Detection Rate (TPR) | **97.28%** (FN 47건) |
| False Positive Rate (FPR) | **0.27%** (FP 2건 / 747건) |
| F1-Attack | **98.57%** |
| ROC-AUC | 0.9953 |

### VulnBank OOD 평가 (out-of-domain, held-out)

| 지표 | 값 |
|------|-----|
| Detection Rate | 91.65% |
| FPR | **0.14%** (FP 3건 / 2,211건) |
| Precision | 99.66% |
| F1-binary | 95.48% |
| ROC-AUC | **0.9992** |

---

## 7. 알려진 한계

| 항목 | 내용 | 영향 |
|------|------|------|
| 파라미터 변조형 공격 | 음수 금액 송금, 권한 탈취 등 정상 API 구조에 악의적 값 삽입 | OOD FNR 8.35% (FN 79건) |
| CMDi 실전 성능 미검증 | CSIC2010 test set에 CMDi 0건 — 합성 데이터로만 학습 | 실제 CMDi 탐지 성능 보장 불가 |
| 단일 OOD 벤치마크 | VulnBank 하나만으로 OOD 일반화 측정 | 다른 도메인 성능 미보장 |
| FP 3건 잔존 | 특수문자 패스워드, `.woff2` 폰트 파일, `GET /` 루트 경로 | 임계값 조정 또는 규칙 후처리로 해소 가능 |

---

## 8. 빠른 연동 테스트

```python
# AI 서버 구동 후 단건 테스트
import requests

response = requests.post("http://localhost:8000/predict", json={
    "raw_input": "GET /products?id=1 OR 1=1-- HTTP/1.1\r\nHost: localhost\r\n\r\n"
})
print(response.json())
# {"classificationScore": 0.97, "cweLabel": "CWE-89"}
```

```bash
# curl 테스트
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"raw_input": "GET /products?id=1 OR 1=1-- HTTP/1.1\r\nHost: localhost\r\n\r\n"}'
```

```python
# predict.py 직접 사용 (AI 서버 없이)
from src.predict import WAFPredictor

predictor = WAFPredictor('/home/gyh3257/waf_model/models/case_f/final')
result = predictor.predict(method='GET', uri='/products?id=1 OR 1=1--', body='')
# {'label': 'SQLi', 'label_id': 1, 'confidence': 0.97, 'scores': {...}}
```

---

## 9. 모델 파일 위치

```bash
# 학습 환경 (WSL2)
/home/gyh3257/waf_model/models/case_f/final/

# 가상환경 활성화
source ~/waf_env/bin/activate

# 추론 테스트
cd ~/waf_model
python src/predict.py --model models/case_f/final \
  --method GET --uri "/products?id=1 OR 1=1--"
```

배포 시 `models/case_f/final/` 디렉토리를 `ai-server/` 하위로 복사하거나 볼륨 마운트.
