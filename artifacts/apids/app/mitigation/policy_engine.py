"""
Policy Engine — maps risk scores to response actions.

Actions (in order of severity):
  BLOCK     — reject the prompt entirely
  SANITIZE  — remove malicious segments, return cleaned text
  REWRITE   — rephrase the prompt using LLM (falls back to SANITIZE)
  ALLOW     — pass through with an audit log entry
"""

from typing import Tuple, Dict

POLICIES: Dict[str, Dict[str, float]] = {
    "strict": {
        "block":    50.0,
        "sanitize": 25.0,
    },
    "standard": {
        "block":    75.0,
        "sanitize": 35.0,
    },
    "lenient": {
        "block":    85.0,
        "sanitize": 50.0,
    },
}

SEVERITY_MAP = [
    (75.0, "CRITICAL"),
    (50.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0,  "LOW"),
]


def get_severity(risk_score: float) -> str:
    for threshold, label in SEVERITY_MAP:
        if risk_score >= threshold:
            return label
    return "LOW"


def decide(risk_score: float, policy: str = "standard", use_llm_rewrite: bool = False) -> Tuple[str, str]:
    """
    Returns (action, severity).

    action: "BLOCK" | "SANITIZE" | "REWRITE" | "ALLOW"
    """
    thresholds = POLICIES.get(policy, POLICIES["standard"])
    severity   = get_severity(risk_score)

    if risk_score >= thresholds["block"]:
        action = "BLOCK"
    elif risk_score >= thresholds["sanitize"]:
        action = "REWRITE" if use_llm_rewrite else "SANITIZE"
    else:
        action = "ALLOW"

    return action, severity


def policy_description(policy: str) -> Dict:
    t = POLICIES.get(policy, POLICIES["standard"])
    return {
        "name":          policy,
        "block_at":      t["block"],
        "sanitize_at":   t["sanitize"],
        "allow_below":   t["sanitize"],
        "description":   {
            "strict":   "Block ≥50, Sanitize ≥25 — maximum protection, highest false-positive rate",
            "standard": "Block ≥75, Sanitize ≥35 — balanced default",
            "lenient":  "Block ≥85, Sanitize ≥50 — minimal disruption, lower protection",
        }.get(policy, ""),
    }
