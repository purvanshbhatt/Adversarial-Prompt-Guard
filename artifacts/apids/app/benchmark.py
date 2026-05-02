"""
Benchmark suite — compares all detection layers head-to-head.

Layers:
  1. Keyword filter (simple baseline)
  2. Rule-based (regex + heuristics)
  3. ML classifier (TF-IDF + LR)
  4. Semantic similarity (sentence-transformer)
  5. Ensemble (combined score)
"""
import re
from typing import List, Dict

from .preprocessing import normalize_text
from .detection.rule_based import RuleBasedDetector
from .detection.ml_classifier import MLClassifier
from .detection.semantic_similarity import SemanticSimilarityDetector
from .metrics.isr import compute_isr, compute_isr_per_layer
from .training.dataset import generate_dataset

# ── Simple keyword baseline ─────────────────────────────────────────────────

KEYWORD_LIST = [
    "ignore", "override", "forget", "bypass", "jailbreak", "DAN",
    "reveal", "system prompt", "no restrictions", "pretend", "roleplay",
    "exfiltrate", "developer mode", "unrestricted", "disregard",
]


def keyword_detect(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in KEYWORD_LIST)


# ── Benchmark runner ────────────────────────────────────────────────────────

def run_benchmark(dataset_size: int = 400, seed: int = 99) -> Dict:
    """
    Run all 5 detection layers on a fresh dataset and return comparison metrics.
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

    dataset = generate_dataset(dataset_size, seed=seed)
    texts = [d["text"] for d in dataset]
    labels = [d["label"] for d in dataset]

    rb = RuleBasedDetector()
    ml = MLClassifier()
    sem = SemanticSimilarityDetector()

    results: Dict[str, List[int]] = {
        "keyword": [],
        "rule_based": [],
        "ml": [],
        "semantic": [],
        "ensemble": [],
    }

    for text in texts:
        norm = normalize_text(text)

        # 1. Keyword
        results["keyword"].append(1 if keyword_detect(text) else 0)

        # 2. Rule-based
        rb_r = rb.detect(text)
        results["rule_based"].append(1 if rb_r["score"] > 20 else 0)

        # 3. ML
        ml_r = ml.predict(norm)
        results["ml"].append(1 if (ml_r["trained"] and ml_r["score"] > 40) else 0)

        # 4. Semantic
        sem_r = sem.compute_similarity(text)
        results["semantic"].append(1 if sem_r["score"] > 35 else 0)

        # 5. Ensemble
        rb_score = rb_r["score"]
        ml_score = ml_r["score"] if ml_r["trained"] else 0.0
        sem_score = sem_r["score"]
        if ml_r["trained"]:
            ens = rb_score * 0.35 + ml_score * 0.40 + sem_score * 0.25
        else:
            ens = rb_score * 0.55 + sem_score * 0.45
        results["ensemble"].append(1 if ens >= 35 else 0)

    # Compute metrics for each layer
    layer_metrics = {}
    for layer, preds in results.items():
        layer_metrics[layer] = {
            "accuracy": round(accuracy_score(labels, preds), 4),
            "precision": round(precision_score(labels, preds, zero_division=0), 4),
            "recall": round(recall_score(labels, preds, zero_division=0), 4),
            "f1": round(f1_score(labels, preds, zero_division=0), 4),
        }

    # ISR per layer
    isr_results = []
    for i, d in enumerate(dataset):
        row = {
            "label": d["label"],
            "category": d.get("category", "unknown"),
            "is_malicious": bool(results["ensemble"][i]),
            "attack_types": [d.get("category", "unknown")] if d["label"] == 1 else [],
        }
        isr_results.append(row)

    from .metrics.isr import compute_isr
    isr_data = compute_isr(isr_results)

    from .metrics.pivs import compute_pivs
    pivs_data = compute_pivs(isr_data)

    # Rank layers by F1
    ranked = sorted(
        [(layer, m["f1"]) for layer, m in layer_metrics.items()],
        key=lambda x: x[1],
        reverse=True,
    )

    return {
        "dataset_size": dataset_size,
        "layer_metrics": layer_metrics,
        "ranking": [{"layer": l, "f1": f} for l, f in ranked],
        "best_layer": ranked[0][0] if ranked else "ensemble",
        "isr": isr_data,
        "pivs": pivs_data,
    }
