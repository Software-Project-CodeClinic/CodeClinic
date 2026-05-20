import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from predict import WAFPredictor

MODEL_PATH = os.environ.get("MODEL_PATH", "models/case_f/final")
_predictor: WAFPredictor | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _predictor
    _predictor = WAFPredictor(MODEL_PATH)
    yield


app = FastAPI(lifespan=lifespan)


class PredictRequest(BaseModel):
    raw_input: str


class PredictResponse(BaseModel):
    classificationScore: float
    cweLabel: str


@app.get("/health")
def health() -> dict:
    # MODEL_PATH 예: "models/case_f/final" → model_name: "case_f"
    parts = MODEL_PATH.replace("\\", "/").rstrip("/").split("/")
    model_name = parts[-2] if len(parts) >= 2 else MODEL_PATH
    return {"status": "ok", "model": model_name}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> PredictResponse:
    if _predictor is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    result = _predictor.predict(req.raw_input)
    return PredictResponse(**result)
