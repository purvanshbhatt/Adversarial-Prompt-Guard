"""
Injection Success Rate (ISR) and related metrics.

ISR = proportion of malicious prompts that bypass the detection system
    = missed_detections / total_malicious

ISR_reduction = ISR_baseline (1.0, unprotected) - ISR_protected
"""
from typing import List, Dict, Any


def compute_isr(results: List[Dict[str, Any]]) -> Dict:
    """
    Compute ISR from a list of detection results.

    Each result must have:
        - 'label': 1 (malicious) or 0 (benign)
        - 'is_malicious': bool  (system prediction)
    """
    malicious = [r for r in results if r.get("label") == 1]
    benign = [r for r in results if r.get("label") == 0]

    if not malicious:
        return {
            "isr_baseline": 1.0,
            "isr_protected": None,
            "isr_reduction": None,
            "false_positive_rate": 0.0,
            "catch_rate": None,
            "missed_attacks": 0,
            "total_attacks": 0,
            "message": "No malicious samples provided.",
        }

    # ISR = fraction of attacks that slip through
    missed = [r for r in malicious if not r.get("is_malicious", False)]
    caught = [r for r in malicious if r.get("is_malicious", False)]

    isr_protected = len(missed) / len(malicious)
    isr_baseline = 1.0
    isr_reduction = isr_baseline - isr_protected
    catch_rate = len(caught) / len(malicious)

    # False positive rate (benign flagged as malicious)
    false_positives = [r for r in benign if r.get("is_malicious", False)]
    fpr = len(false_positives) / len(benign) if benign else 0.0

    # Per-category ISR
    categories = {}
    for r in malicious:
        for cat in r.get("attack_types", ["unknown"]) or ["unknown"]:
            if cat not in categories:
                categories[cat] = {"total": 0, "missed": 0}
            categories[cat]["total"] += 1
            if not r.get("is_malicious", False):
                categories[cat]["missed"] += 1

    per_category_isr = {
        cat: round(v["missed"] / v["total"], 4) if v["total"] > 0 else 0.0
        for cat, v in categories.items()
    }

    return {
        "isr_baseline": 1.0,
        "isr_protected": round(isr_protected, 4),
        "isr_reduction": round(isr_reduction, 4),
        "catch_rate": round(catch_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "missed_attacks": len(missed),
        "caught_attacks": len(caught),
        "total_attacks": len(malicious),
        "total_benign": len(benign),
        "per_category_isr": per_category_isr,
    }


def compute_isr_per_layer(
    results: List[Dict[str, Any]],
    score_key: str,
    threshold: float,
) -> Dict:
    """Compute ISR for a single detection layer identified by score_key."""
    for r in results:
        r["_layer_flag"] = r.get(score_key, 0) >= threshold

    malicious = [r for r in results if r.get("label") == 1]
    if not malicious:
        return {"isr": None, "catch_rate": None}

    missed = [r for r in malicious if not r["_layer_flag"]]
    return {
        "isr": round(len(missed) / len(malicious), 4),
        "catch_rate": round(1 - len(missed) / len(malicious), 4),
        "threshold": threshold,
        "score_key": score_key,
    }
