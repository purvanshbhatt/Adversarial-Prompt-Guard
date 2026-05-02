from typing import Any, Dict, List

from .base import AgentBase
from .shared_memory import EventStore


class RiskScoringAgent(AgentBase):
    name = "risk_scoring"
    version = "1.0.0"
    description = "Enterprise risk scoring combining ML, rule-based, semantic, behavior, and correlation signals"

    BEHAVIOR_MODIFIER_MAX = 1.50
    CORRELATION_BONUS_MAX = 20.0

    def process(
        self,
        prompt_result: Dict[str, Any],
        correlation_result: Dict[str, Any],
        session_id: str,
    ) -> Dict[str, Any]:
        store = EventStore.get()
        risk_trend = store.get_session_risk_trend(session_id)

        rule_score = prompt_result.get("rule_based_score", 0.0)
        ml_score = prompt_result.get("ml_score", 0.0)
        sem_score = prompt_result.get("semantic_score", 0.0)
        obf_score = prompt_result.get("obfuscation_score", 0.0)
        ml_prediction = prompt_result.get("ml_prediction", "unknown")

        if ml_prediction != "unknown":
            base = rule_score * 0.28 + ml_score * 0.36 + sem_score * 0.22 + obf_score * 0.14
        else:
            base = rule_score * 0.55 + sem_score * 0.30 + obf_score * 0.15

        behavior_modifier = 1.0
        if len(risk_trend) >= 2:
            avg_session = sum(risk_trend) / len(risk_trend)
            if avg_session >= 60:
                behavior_modifier = 1.30
            elif avg_session >= 40:
                behavior_modifier = 1.15
            elif avg_session >= 25:
                behavior_modifier = 1.05

        session_events = store.get_session_events(session_id, window_seconds=600)
        session_count = len(session_events)
        if session_count >= 10:
            behavior_modifier = min(self.BEHAVIOR_MODIFIER_MAX, behavior_modifier + 0.15)
        elif session_count >= 5:
            behavior_modifier = min(self.BEHAVIOR_MODIFIER_MAX, behavior_modifier + 0.08)

        correlation_bonus = 0.0
        corr_score = correlation_result.get("correlation_score", 0.0)
        if correlation_result.get("coordinated_attack"):
            correlation_bonus = min(self.CORRELATION_BONUS_MAX, corr_score * 0.3)

        enterprise_score = min(100.0, base * behavior_modifier + correlation_bonus)
        enterprise_score = round(enterprise_score, 1)

        if enterprise_score >= 80:
            risk_level = "CRITICAL"
            recommended_action = "Block request immediately. Escalate to SOC team. Invalidate session."
        elif enterprise_score >= 60:
            risk_level = "HIGH"
            recommended_action = "Block request. Flag session for review. Increase monitoring."
        elif enterprise_score >= 40:
            risk_level = "MEDIUM"
            recommended_action = "Rate-limit session. Log for review. Monitor subsequent requests."
        elif enterprise_score >= 20:
            risk_level = "LOW"
            recommended_action = "Allow with enhanced logging. Watch for escalation."
        else:
            risk_level = "SAFE"
            recommended_action = "Allow request. Standard logging applies."

        rationale_parts: List[str] = []
        rationale_parts.append(
            f"Base score {base:.1f} computed from rule ({rule_score:.0f}), "
            f"ML ({ml_score:.0f}), semantic ({sem_score:.0f}), obfuscation ({obf_score:.0f})."
        )
        if behavior_modifier > 1.0:
            rationale_parts.append(
                f"Behavior modifier ×{behavior_modifier:.2f} applied: "
                f"session shows {session_count} prior events with avg risk {sum(risk_trend)/len(risk_trend):.1f}."
                if risk_trend else
                f"Behavior modifier ×{behavior_modifier:.2f} applied: session has {session_count} prior events."
            )
        if correlation_bonus > 0:
            rationale_parts.append(
                f"Correlation bonus +{correlation_bonus:.1f} added: coordinated attack indicators detected."
            )

        return {
            "agent": self.name,
            "enterprise_risk_score": enterprise_score,
            "risk_level": risk_level,
            "base_score": round(base, 1),
            "behavior_modifier": round(behavior_modifier, 3),
            "correlation_bonus": round(correlation_bonus, 1),
            "session_event_count": session_count,
            "recommended_action": recommended_action,
            "rationale": " ".join(rationale_parts),
            "score_breakdown": {
                "rule_weighted": round(rule_score * (0.28 if ml_prediction != "unknown" else 0.55), 1),
                "ml_weighted": round(ml_score * 0.36, 1) if ml_prediction != "unknown" else 0,
                "semantic_weighted": round(sem_score * (0.22 if ml_prediction != "unknown" else 0.30), 1),
                "obfuscation_weighted": round(obf_score * (0.14 if ml_prediction != "unknown" else 0.15), 1),
                "behavior_adjustment": round(base * (behavior_modifier - 1.0), 1),
                "correlation_bonus": round(correlation_bonus, 1),
            },
        }
