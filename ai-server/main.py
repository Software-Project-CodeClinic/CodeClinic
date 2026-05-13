import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> PredictResponse:
    result = _predictor.predict(req.raw_input)
    return PredictResponse(**result)
