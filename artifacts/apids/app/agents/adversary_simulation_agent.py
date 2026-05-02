import random
from typing import Any, Callable, Dict, List, Optional

from .base import AgentBase


class AdversarySimulationAgent(AgentBase):
    name = "adversary_simulation"
    version = "1.0.0"
    description = "AI-powered adversarial attack generator that probes the detection pipeline"

    def __init__(self, generate_attacks_fn: Callable, run_analysis_fn: Callable):
        self._generate = generate_attacks_fn
        self._analyze = run_analysis_fn

    def process(
        self,
        strategy: str = "all",
        n: int = 6,
        goal: str = "bypass safety restrictions",
        difficulty_min: int = 1,
        difficulty_max: int = 5,
        feed_to_detection: bool = True,
    ) -> Dict[str, Any]:
        from ..adversarial.strategies import ALL_STRATEGIES

        strategies_to_run = ALL_STRATEGIES if strategy == "all" else [strategy]
        per_strategy = max(1, n // len(strategies_to_run))

        all_attacks: List[Dict] = []
        detection_results: List[Dict] = []
        bypasses: List[Dict] = []
        detected: List[Dict] = []

        for strat in strategies_to_run:
            try:
                batch = self._generate(
                    strategy=strat,
                    n=per_strategy,
                    goal=goal,
                    difficulty_min=difficulty_min,
                    difficulty_max=difficulty_max,
                    use_llm=False,
                )
                attacks = batch.get("attacks", [])
                all_attacks.extend(attacks)

                if feed_to_detection:
                    for atk in attacks:
                        prompt = atk.get("prompt", "")
                        det = self._analyze(prompt)
                        entry = {
                            "prompt": prompt[:200],
                            "strategy": strat,
                            "template_id": atk.get("template_id", ""),
                            "difficulty": atk.get("difficulty", 1),
                            "risk_score": det["risk_score"],
                            "is_malicious": det["is_malicious"],
                            "attack_types": det["attack_types"],
                        }
                        detection_results.append(entry)
                        if det["is_malicious"]:
                            detected.append(entry)
                        else:
                            bypasses.append(entry)
            except Exception:
                continue

        total = len(detection_results)
        detected_count = len(detected)
        bypass_count = len(bypasses)
        robustness = round((detected_count / total * 100) if total > 0 else 100.0, 1)

        bypasses_sorted = sorted(bypasses, key=lambda x: -x["risk_score"])
        hardest_bypass = bypasses_sorted[0] if bypasses_sorted else None

        return {
            "agent": self.name,
            "strategies_tested": strategies_to_run,
            "total_attacks": total,
            "detected_count": detected_count,
            "bypass_count": bypass_count,
            "robustness_score": robustness,
            "bypass_rate": round(bypass_count / total, 4) if total > 0 else 0.0,
            "hardest_bypass": hardest_bypass,
            "bypasses": bypasses_sorted[:10],
            "detection_results": detection_results,
        }
