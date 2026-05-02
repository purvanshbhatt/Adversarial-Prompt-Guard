from typing import Any, Dict, Optional

from .base import AgentBase


class PromptSecurityAgent(AgentBase):
    name = "prompt_security"
    version = "2.0.0"
    description = "Multi-layer prompt injection detector (rule-based + ML + semantic + obfuscation)"

    def __init__(self, run_analysis_fn):
        self._run_analysis = run_analysis_fn

    def process(self, prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
        result = self._run_analysis(prompt)
        score = result["risk_score"]

        if score >= 75:
            severity = "CRITICAL"
        elif score >= 55:
            severity = "HIGH"
        elif score >= 35:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "INFO"

        return {
            "agent": self.name,
            "severity": severity,
            "risk_score": result["risk_score"],
            "is_malicious": result["is_malicious"],
            "attack_types": result["attack_types"],
            "rule_based_score": result["rule_based_score"],
            "ml_score": result["ml_score"],
            "semantic_score": result["semantic_score"],
            "obfuscation_score": result["obfuscation_score"],
            "obfuscation_techniques": result["obfuscation_techniques"],
            "ml_prediction": result["ml_prediction"],
            "ml_confidence": result["ml_confidence"],
            "explanation": result["explanation"],
            "suspicious_tokens": result["suspicious_tokens"],
            "most_similar_pattern": result.get("most_similar_pattern"),
        }
