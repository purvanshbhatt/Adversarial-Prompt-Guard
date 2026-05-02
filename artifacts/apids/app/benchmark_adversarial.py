"""
Adversarial benchmark mode — runs the attack generator + mutation engine
against the detection system and produces ISR/PIVS/F1 metrics comparable
with the synthetic and real-world benchmarks.

Two sub-modes:
  static      — fixed prompts from SAMPLE_PROMPTS (evaluation/realworld.py)
  adversarial — prompts generated + mutated by the adversary module

Outputs a unified comparison dict so the dashboard can plot side-by-side.
"""

import time
from typing import Dict, List, Optional

from .adversary.generator import AttackGenerator, CATEGORY_WEIGHTS
from .adversary.mutator import PromptMutator, ALL_STRATEGIES
from .detection.rule_based import RuleBasedDetector
from .detection.ml_classifier import MLClassifier
from .detection.semantic_similarity import SemanticSimilarityDetector
from .obfuscation import detect_obfuscation
from .metrics.isr import compute_isr
from .metrics.pivs import compute_pivs

DETECTION_THRESHOLD = 35.0


def _score_prompt(text: str, rb, ml, sem) -> tuple:
    """Run all detection layers and return (risk_score, is_malicious)."""
    rb_r  = rb.detect(text)
    ml_r  = ml.predict(text)
    sem_r = sem.compute_similarity(text)
    obf_r = detect_obfuscation(text)

    rb_score  = rb_r["score"]
    ml_score  = ml_r["score"]
    sem_score = sem_r["score"]
    obf_score = obf_r["obfuscation_score"]

    if ml_r["trained"]:
        risk = rb_score * 0.32 + ml_score * 0.38 + sem_score * 0.20 + obf_score * 0.10
    else:
        risk = rb_score * 0.60 + sem_score * 0.30 + obf_score * 0.10

    risk = round(min(risk, 100.0), 1)
    return risk, risk >= DETECTION_THRESHOLD


def run_static_benchmark(n_malicious: int = 50, n_benign: int = 50) -> Dict:
    """
    Static benchmark — use the curated sample dataset (no generation or mutation).
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from .evaluation.realworld import SAMPLE_PROMPTS

    rb  = RuleBasedDetector()
    ml  = MLClassifier()
    sem = SemanticSimilarityDetector()

    malicious_pool = [p for p in SAMPLE_PROMPTS if p["label"] == 1][:n_malicious]
    benign_pool    = [p for p in SAMPLE_PROMPTS if p["label"] == 0][:n_benign]
    dataset = malicious_pool + benign_pool

    y_true, y_pred, isr_rows, detail = [], [], [], []
    t0 = time.time()

    for row in dataset:
        text  = row["prompt"]
        label = row["label"]
        risk, detected = _score_prompt(text, rb, ml, sem)

        y_true.append(label)
        y_pred.append(1 if detected else 0)
        isr_rows.append({
            "label":        label,
            "is_malicious": detected,
            "attack_types": [row.get("category", "unknown")] if label == 1 else [],
        })
        detail.append({
            "prompt":    text[:100],
            "label":     label,
            "predicted": 1 if detected else 0,
            "risk_score": risk,
            "category":  row.get("category", "unknown"),
            "mutated":   False,
            "mode":      "static",
        })

    isr  = compute_isr(isr_rows)
    pivs = compute_pivs(isr)
    elapsed = round(time.time() - t0, 2)

    return {
        "mode":         "static",
        "dataset_size": len(dataset),
        "n_malicious":  len(malicious_pool),
        "n_benign":     len(benign_pool),
        "elapsed_sec":  elapsed,
        "metrics": {
            "accuracy":  round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
        },
        "isr":    isr,
        "pivs":   pivs,
        "detail": detail,
    }


def run_adversarial_benchmark(
    n_attacks:        int = 50,
    n_benign:         int = 30,
    max_mutations:    int = 4,
    complexity:       str = "high",
    categories:       Optional[List[str]] = None,
) -> Dict:
    """
    Adversarial benchmark — generate + mutate prompts, measure detection system's
    robustness against an adaptive attacker.

    Returns same structure as run_static_benchmark for side-by-side comparison.
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from .evaluation.realworld import SAMPLE_PROMPTS

    cats = categories or list(CATEGORY_WEIGHTS.keys())
    gen  = AttackGenerator(seed=123)
    mut  = PromptMutator(seed=456)

    rb  = RuleBasedDetector()
    ml  = MLClassifier()
    sem = SemanticSimilarityDetector()

    y_true, y_pred, isr_rows, detail = [], [], [], []
    mutation_log: List[Dict] = []
    bypassed_count = 0
    total_mutations = 0

    t0 = time.time()

    # ── Adversarial malicious prompts ──────────────────────────────────────────
    for i in range(n_attacks):
        cat    = cats[i % len(cats)]
        attack = gen.generate(category=cat, complexity=complexity)
        prompt = attack.text
        label  = 1

        risk, detected = _score_prompt(prompt, rb, ml, sem)
        mutation_chain: List[str] = [prompt[:80]]
        used_strategies: List[str] = []
        final_risk = risk
        final_detected = detected
        mutations_used = 0

        # Mutate if detected — try up to max_mutations strategies
        if detected:
            strat_pool = list(ALL_STRATEGIES)
            for strat in strat_pool[:max_mutations]:
                mutated = mut.mutate(prompt, strat)
                m_risk, m_detected = _score_prompt(mutated, rb, ml, sem)
                mutations_used += 1
                total_mutations += 1
                mutation_chain.append(mutated[:80])
                used_strategies.append(strat.value)
                if not m_detected:
                    # Bypass achieved
                    prompt         = mutated
                    final_risk     = m_risk
                    final_detected = False
                    mut.record_success(strat)
                    bypassed_count += 1
                    break
                else:
                    prompt    = mutated
                    final_risk = m_risk

        predicted = 1 if final_detected else 0
        y_true.append(label)
        y_pred.append(predicted)
        isr_rows.append({
            "label":        label,
            "is_malicious": final_detected,
            "attack_types": [cat],
        })
        detail.append({
            "prompt":      attack.text[:100],
            "final_prompt": prompt[:100],
            "label":       label,
            "predicted":   predicted,
            "risk_score":  final_risk,
            "category":    cat,
            "mutated":     mutations_used > 0,
            "mutations":   mutations_used,
            "strategies":  used_strategies,
            "bypassed":    not final_detected,
            "mode":        "adversarial",
        })
        if used_strategies:
            mutation_log.append({
                "original_prompt": attack.text[:80],
                "final_prompt":    prompt[:80],
                "strategies":      used_strategies,
                "bypassed":        not final_detected,
                "initial_risk":    risk,
                "final_risk":      final_risk,
            })

    # ── Benign prompts (same as static for fair comparison) ────────────────────
    benign_pool = [p for p in SAMPLE_PROMPTS if p["label"] == 0][:n_benign]
    for row in benign_pool:
        text  = row["prompt"]
        risk, detected = _score_prompt(text, rb, ml, sem)
        y_true.append(0)
        y_pred.append(1 if detected else 0)
        isr_rows.append({
            "label":        0,
            "is_malicious": detected,
            "attack_types": [],
        })
        detail.append({
            "prompt":    text[:100],
            "label":     0,
            "predicted": 1 if detected else 0,
            "risk_score": risk,
            "category":  "benign",
            "mutated":   False,
            "mode":      "adversarial",
        })

    isr  = compute_isr(isr_rows)
    pivs = compute_pivs(isr)
    elapsed = round(time.time() - t0, 2)

    # Mutation strategy effectiveness
    strat_stats = mut.strategy_stats()

    return {
        "mode":             "adversarial",
        "dataset_size":     len(detail),
        "n_attacks":        n_attacks,
        "n_benign":         n_benign,
        "n_bypassed":       bypassed_count,
        "bypass_rate":      round(bypassed_count / max(n_attacks, 1) * 100, 1),
        "total_mutations":  total_mutations,
        "avg_mutations":    round(total_mutations / max(n_attacks, 1), 1),
        "elapsed_sec":      elapsed,
        "metrics": {
            "accuracy":  round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
        },
        "isr":              isr,
        "pivs":             pivs,
        "mutation_log":     mutation_log[:20],
        "mutation_strategies": strat_stats,
        "detail":           detail,
    }


def compare_modes(
    static_result:      Optional[Dict] = None,
    adversarial_result: Optional[Dict] = None,
    realworld_result:   Optional[Dict] = None,
) -> Dict:
    """
    Produce a comparison table across static / adversarial / real-world benchmarks.
    """
    results = {}
    if static_result:
        results["static"] = static_result
    if adversarial_result:
        results["adversarial"] = adversarial_result
    if realworld_result:
        results["real_world"] = realworld_result

    comparison = {}
    for metric in ("accuracy", "precision", "recall", "f1"):
        comparison[metric] = {
            mode: round(data.get("metrics", {}).get(metric, 0), 4)
            for mode, data in results.items()
        }

    comparison["isr_protected"] = {
        mode: round((data.get("isr", {}).get("isr_protected") or 0), 4)
        for mode, data in results.items()
    }
    comparison["pivs"] = {
        mode: round(data.get("pivs", {}).get("pivs", 0), 1)
        for mode, data in results.items()
    }

    # Generalization gap: static → adversarial F1 drop
    gen_gaps = {}
    f1_static = results.get("static", {}).get("metrics", {}).get("f1", None)
    for mode in ("adversarial", "real_world"):
        f1_other = results.get(mode, {}).get("metrics", {}).get("f1", None)
        if f1_static is not None and f1_other is not None:
            delta = round(float(f1_static) - float(f1_other), 4)
            gen_gaps[f"static_vs_{mode}"] = {
                "delta":     delta,
                "direction": "degraded" if delta > 0.05 else "robust" if delta >= -0.05 else "improved",
                "f1_drop_pct": round(delta * 100, 1),
            }

    return {
        "modes_included": list(results.keys()),
        "per_metric":     comparison,
        "generalization_gaps": gen_gaps,
        "best_f1_mode":   max(comparison.get("f1", {}).items(), key=lambda x: x[1])[0]
                          if comparison.get("f1") else None,
        "worst_f1_mode":  min(comparison.get("f1", {}).items(), key=lambda x: x[1])[0]
                          if comparison.get("f1") else None,
    }


def export_research_table(comparison: Dict, mode_results: Dict) -> str:
    """
    Export comparison as a research-ready CSV + LaTeX-style table string.
    """
    import csv
    import io

    out = io.StringIO()
    w   = csv.writer(out)

    w.writerow(["=== AURORASOC BENCHMARK COMPARISON TABLE ==="])
    w.writerow(["Generated by AuroraSOC — github.com/your-org/aurorasoc"])
    w.writerow([])

    modes = comparison.get("modes_included", [])
    header = ["Metric"] + [m.replace("_", " ").title() for m in modes]
    w.writerow(header)

    for metric in ("accuracy", "precision", "recall", "f1"):
        row = [metric.title()]
        for mode in modes:
            val = comparison.get("per_metric", {}).get(metric, {}).get(mode, 0)
            row.append(f"{val*100:.1f}%")
        w.writerow(row)

    w.writerow(["ISR (Protected)"] + [
        f"{comparison.get('per_metric',{}).get('isr_protected',{}).get(m,0)*100:.1f}%"
        for m in modes
    ])
    w.writerow(["PIVS Score"] + [
        f"{comparison.get('per_metric',{}).get('pivs',{}).get(m,0):.1f}"
        for m in modes
    ])

    w.writerow([])
    w.writerow(["=== GENERALIZATION GAPS ==="])
    for gap_key, gap_val in comparison.get("generalization_gaps", {}).items():
        w.writerow([gap_key.replace("_", " ").title(),
                    f"ΔF1={gap_val['f1_drop_pct']:+.1f}%",
                    gap_val.get("direction", "")])

    w.writerow([])
    w.writerow(["=== LATEX TABLE (copy into paper) ==="])
    w.writerow([r"\begin{tabular}{l" + "c" * len(modes) + "}"])
    w.writerow([r"\hline"])
    w.writerow(["Metric & " + " & ".join(m.replace("_"," ").title() for m in modes) + r" \\"])
    w.writerow([r"\hline"])
    for metric in ("Accuracy", "Precision", "Recall", "F1"):
        mk = metric.lower()
        vals = [f"{comparison.get('per_metric',{}).get(mk,{}).get(m,0)*100:.1f}" for m in modes]
        w.writerow([f"{metric} & " + " & ".join(vals) + r" \\"])
    isr_vals = [f"{comparison.get('per_metric',{}).get('isr_protected',{}).get(m,0)*100:.1f}" for m in modes]
    w.writerow(["ISR$_{protected}$ & " + " & ".join(isr_vals) + r" \\"])
    pivs_vals = [f"{comparison.get('per_metric',{}).get('pivs',{}).get(m,0):.1f}" for m in modes]
    w.writerow(["PIVS & " + " & ".join(pivs_vals) + r" \\"])
    w.writerow([r"\hline"])
    w.writerow([r"\end{tabular}"])

    w.writerow([])
    w.writerow(["=== PER-MODE DETAILS ==="])
    for mode, data in mode_results.items():
        w.writerow([])
        w.writerow([f"--- {mode.upper()} ---"])
        w.writerow(["Dataset Size", data.get("dataset_size", 0)])
        w.writerow(["Elapsed (sec)", data.get("elapsed_sec", 0)])
        if mode == "adversarial":
            w.writerow(["Bypass Rate", f"{data.get('bypass_rate',0):.1f}%"])
            w.writerow(["Avg Mutations", data.get("avg_mutations", 0)])

    return out.getvalue()
