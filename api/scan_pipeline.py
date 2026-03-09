from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from filters.regex_filter import regex_scan
from models.ml_model import predict_prompt
from policy_engine.policy_engine import evaluate_policy

# ML score weight
ML_MALICIOUS_WEIGHT = 50   # points added to total_score when ML flags prompt
SCORE_CAP = 100


# Result container
@dataclass
class ScanResult:
    action: str                        # allow | rewrite | redact | block
    categories: List[str] = field(default_factory=list)
    total_score: int = 0
    ml_label: int = 0                  # 0 = benign, 1 = malicious
    ml_confidence: float = 0.0
    regex_score: int = 0
    ml_score: int = 0

    def is_blocked(self) -> bool:
        return self.action == "block"

    def is_clean(self) -> bool:
        return self.action == "allow"

    def __repr__(self) -> str:
        return (
            f"ScanResult(action={self.action!r}, score={self.total_score}, "
            f"categories={self.categories}, "
            f"ml_label={self.ml_label}, ml_confidence={self.ml_confidence:.2%})"
        )


# Core pipeline
def scan_prompt(prompt: str) -> ScanResult:
    """
    Full scan pipeline for a single prompt string.

    Steps
    -----
    1. Regex + PII scan  → regex_score, categories
    2. ML inference      → ml_label, confidence
    3. Score combination → total_score (capped at SCORE_CAP)
    4. Policy decision   → action

    Returns
    -------
    ScanResult dataclass with all intermediate signals attached.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        return ScanResult(action="allow")

    # 1. Regex + PII
    regex_score, categories = regex_scan(prompt)

    # 2. ML model
    ml_label, confidence = predict_prompt(prompt)

    if ml_label == 1:
        categories.append("ml_detected_malicious")
        ml_score = ML_MALICIOUS_WEIGHT
    else:
        ml_score = 0

    # 3. Combine & cap
    total_score = min(regex_score + ml_score, SCORE_CAP)

    # 4. Policy
    action = evaluate_policy(total_score, categories)

    return ScanResult(
        action=action,
        categories=categories,
        total_score=total_score,
        ml_label=ml_label,
        ml_confidence=confidence,
        regex_score=regex_score,
        ml_score=ml_score,
    )


def scan_batch(prompts: List[str]) -> List[ScanResult]:
    """
    Scan a list of prompts. Returns one ScanResult per prompt.
    Useful for bulk pre-filtering before sending to an LLM.
    """
    return [scan_prompt(p) for p in prompts]


def scan_and_raise(prompt: str) -> ScanResult:
    """
    Scan a prompt and raise a BlockedPromptError if the policy
    decision is 'block'. Useful as a guard in request handlers.
    """
    result = scan_prompt(prompt)
    if result.is_blocked():
        raise BlockedPromptError(result)
    return result

# Custom exception
class BlockedPromptError(Exception):
    """Raised by scan_and_raise() when a prompt is blocked."""

    def __init__(self, result: ScanResult):
        self.result = result
        super().__init__(
            f"Prompt blocked — score={result.total_score}, "
            f"categories={result.categories}"
        )