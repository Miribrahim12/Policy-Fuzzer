import json
import os
import sys
from typing import List, Literal, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # pipeline.py, llm.py, attack.py ... use flat imports
load_dotenv()

USE_MOCK = os.getenv("USE_MOCK", "true").strip().lower() == "true"
CACHE_DIR = os.path.join(HERE, "..", "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "last_run.json")

app = FastAPI(title="Policy Fuzzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Shared data contract ----------
class Rule(BaseModel):
    id: str
    text: str
    type: Literal["limit", "approval", "condition", "deadline"]


class Finding(BaseModel):
    rule_id: str
    attacker: Literal["fraudster", "lazy", "technicalist"]
    scenario: str
    severity: Literal["low", "medium", "high"]
    verified: bool
    fix: str
    estimated_loss_azn: int
    # optional extras produced by the real pipeline
    reason: Optional[str] = None
    policy_basis: Optional[str] = None
    attackers: Optional[List[str]] = None
    duplicates: Optional[int] = None


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeResponse(BaseModel):
    rules: List[Rule]
    findings: List[Finding]
    stats: Optional[dict] = None


# ---------- Mock data ----------
MOCK_RESPONSE = {
    "rules": [
        {
            "id": "R1",
            "text": "Expenses up to 700 AZN per receipt are reimbursed without manager approval.",
            "type": "limit",
        },
        {
            "id": "R2",
            "text": "Expense reports must be submitted within 30 days of purchase, otherwise they are rejected unless a reasonable justification is provided.",
            "type": "deadline",
        },
    ],
    "findings": [
        {
            "rule_id": "R1",
            "attacker": "lazy",
            "scenario": "An employee files several personal taxi rides as one 'business trip' entry under the limit and attaches no receipts, because the rule never requires receipts for amounts below 700 AZN.",
            "severity": "low",
            "verified": True,
            "fix": "Require a receipt or ride-hailing statement for every claim, regardless of amount.",
            "estimated_loss_azn": 6500,
        },
        {
            "rule_id": "R1",
            "attacker": "fraudster",
            "scenario": "Split a single 1,800 AZN client dinner into three 600 AZN receipts on consecutive days. Each one stays under the 700 AZN limit, so none needs manager approval.",
            "severity": "high",
            "verified": True,
            "fix": "Aggregate expenses per employee and vendor per week, and apply the approval threshold to the total.",
            "estimated_loss_azn": 45000,
        },
        {
            "rule_id": "R2",
            "attacker": "technicalist",
            "scenario": "Submit a report five months late with the justification 'I was very busy'. The policy never defines 'reasonable justification', so the claim cannot be rejected as written.",
            "severity": "medium",
            "verified": True,
            "fix": "Define accepted justifications (illness, official travel, system outage) and require manager sign-off for late reports.",
            "estimated_loss_azn": 18000,
        },
    ],
}


# ---------- Helpers ----------
def save_cache(result: dict) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
    except Exception as e:  # cache must never break a demo
        print(f"[cache] could not write: {e}", file=sys.stderr)


def check_text(text: str) -> None:
    if not text.strip():
        raise HTTPException(status_code=400, detail="Policy text is empty.")


# ---------- Endpoints ----------
@app.get("/health")
def health():
    return {"status": "ok", "mock": USE_MOCK}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    check_text(req.text)

    if USE_MOCK:
        return MOCK_RESPONSE

    try:
        from pipeline import run

        result = run(req.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {e}")

    if not result:
        raise HTTPException(status_code=500, detail="Pipeline returned nothing.")
    save_cache(result)
    return result


@app.post("/analyze/stream")
def analyze_stream(req: AnalyzeRequest):
    """Server-Sent Events: one JSON event per pipeline stage.
    Events: rules, candidates, judged, finding (one per loophole), done, error."""
    check_text(req.text)

    def gen():
        try:
            if USE_MOCK:
                yield _sse({"stage": "rules", "rules": MOCK_RESPONSE["rules"]})
                for f in MOCK_RESPONSE["findings"]:
                    yield _sse({"stage": "finding", "finding": f})
                yield _sse({"stage": "done", "result": MOCK_RESPONSE})
                return
            from pipeline import run_stream

            for ev in run_stream(req.text):
                if ev["stage"] == "done":
                    save_cache(ev["result"])
                yield _sse(ev)
        except Exception as e:
            yield _sse({"stage": "error", "detail": str(e)})

    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


@app.get("/demo", response_model=AnalyzeResponse)
def demo():
    """Last successful real run, served with no LLM call (offline demo fallback)."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    return MOCK_RESPONSE