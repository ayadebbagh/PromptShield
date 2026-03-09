"""
main.py  —  PromptShield REST API
Run: uvicorn main:app --reload
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import time

from scan_pipeline import scan_prompt, scan_batch, BlockedPromptError

app = FastAPI(
    title="PromptShield API",
    description="Prompt injection & PII detection firewall",
    version="1.0.0"
)

# Allow the demo frontend to call the API from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Schemas

class ScanRequest(BaseModel):
    prompt: str

class BatchScanRequest(BaseModel):
    prompts: List[str]

class ScanResponse(BaseModel):
    action: str
    total_score: int
    regex_score: int
    ml_score: int
    ml_label: int
    ml_confidence: float
    categories: List[str]
    latency_ms: float


# Routes 

@app.get("/")
def root():
    return {"status": "ok", "service": "PromptShield"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    t0 = time.perf_counter()
    result = scan_prompt(req.prompt)
    latency = (time.perf_counter() - t0) * 1000

    return ScanResponse(
        action=result.action,
        total_score=result.total_score,
        regex_score=result.regex_score,
        ml_score=result.ml_score,
        ml_label=result.ml_label,
        ml_confidence=round(result.ml_confidence, 4),
        categories=result.categories,
        latency_ms=round(latency, 1),
    )


@app.post("/scan/batch")
def scan_batch_endpoint(req: BatchScanRequest):
    if not req.prompts:
        raise HTTPException(status_code=400, detail="prompts list must not be empty")
    if len(req.prompts) > 50:
        raise HTTPException(status_code=400, detail="max 50 prompts per batch")

    t0 = time.perf_counter()
    results = scan_batch(req.prompts)
    latency = (time.perf_counter() - t0) * 1000

    return {
        "results": [
            {
                "prompt_preview": p[:60] + "..." if len(p) > 60 else p,
                "action": r.action,
                "total_score": r.total_score,
                "categories": r.categories,
                "ml_confidence": round(r.ml_confidence, 4),
            }
            for p, r in zip(req.prompts, results)
        ],
        "total_latency_ms": round(latency, 1),
        "count": len(results),
    }