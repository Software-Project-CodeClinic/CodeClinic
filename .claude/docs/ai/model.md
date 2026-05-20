# AI 모델 · FastAPI 서버 (AI/ML 담당)

> 담당: 영현 / 브랜치: `feat/ai/fastapi-server`, `feat/ai/model-training`

## 모델 스펙

| 항목 | 값 |
|------|----|
| 베이스 모델 | `distilbert-base-uncased` |
| 분류 클래스 | 5클래스 (NORMAL, CWE-89, CWE-79, CWE-78, CWE-22) |
| 학습 환경 | RTX 3060 12GB, Ubuntu 24.04 (WSL2), PyTorch 2.5.1 |
| 하이퍼파라미터 | max_length=128, lr=2e-5, batch=16, epoch=5 |
| 채택 케이스 | case_g (정확도 90.23%, `--decode-uri` 모드 권장) |

## FastAPI 서버

```python
# ai-server/main.py
from transformers import pipeline

classifier = pipeline("text-classification", model="<모델 경로 또는 Hub ID>")

@app.post("/predict")
def predict(req: PredictRequest):
    results = classifier(req.raw_input, return_all_scores=True)
    top = max(results[0], key=lambda x: x["score"])
    return {
        "classificationScore": top["score"],
        "cweLabel": top["label"]   # argmax 출력 그대로
    }
```

**엔드포인트 계약** — 변경 시 `interface` 이슈 생성 후 양쪽 합의 필요:

```
POST /predict
Request : { "raw_input": "<HTTP 요청 문자열>" }
Response: { "classificationScore": float, "cweLabel": string }
```

## 참고 공개 모델

| 용도 | Hub ID |
|------|--------|
| SQLi 탐지 | `cybersectony/sql-injection-attack-detection-distilbert` |
| 보안 특화 BERT | `jackaduma/SecBERT` |
