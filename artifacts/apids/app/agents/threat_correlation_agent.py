from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import AgentBase
from .shared_memory import EventStore


class ThreatCorrelationAgent(AgentBase):
    name = "threat_correlation"
    version = "1.0.0"
    description = "Correlates attack patterns, session behavior, and coordinated threat campaigns"

    VELOCITY_THRESHOLD = 5
    VELOCITY_WINDOW = 60
    PATTERN_THRESHOLD = 3
    PATTERN_WINDOW = 3600
    ESCALATION_THRESHOLD = 15.0

    def process(
        self,
        session_id: str,
        current_event_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        store = EventStore.get()

        session_events = store.get_session_events(session_id, window_seconds=600)
        recent_events = store.get_recent_events(window_seconds=self.VELOCITY_WINDOW)
        pattern_counts = store.get_attack_pattern_counts(window_seconds=self.PATTERN_WINDOW)
        risk_trend = store.get_session_risk_trend(session_id)

        insights: List[Dict] = []
        coordinated = False
        campaign_detected = False

        velocity = len(recent_events)
        if velocity >= self.VELOCITY_THRESHOLD:
            coordinated = True
            insights.append({
                "type": "high_velocity_attack",
                "severity": "HIGH",
                "description": (
                    f"High-velocity attack detected: {velocity} events in the last "
                    f"{self.VELOCITY_WINDOW}s. Possible automated attack campaign."
                ),
                "evidence": {"events_per_minute": round(velocity * 60 / self.VELOCITY_WINDOW, 1)},
            })

        for attack_type, count in pattern_counts.items():
            if count >= self.PATTERN_THRESHOLD:
                campaign_detected = True
                insights.append({
                    "type": "repeated_attack_pattern",
                    "severity": "MEDIUM",
                    "description": (
                        f"Repeated '{attack_type.replace('_', ' ').title()}' pattern detected "
                        f"{count}x in the last hour. Possible targeted campaign."
                    ),
                    "evidence": {"attack_type": attack_type, "count": count},
                })

        if len(risk_trend) >= 3:
            slope = risk_trend[-1] - risk_trend[0]
            if slope >= self.ESCALATION_THRESHOLD:
                coordinated = True
                insights.append({
                    "type": "risk_escalation",
                    "severity": "HIGH",
                    "description": (
                        f"Risk score escalation detected in session: "
                        f"{risk_trend[0]:.1f} → {risk_trend[-1]:.1f} (+{slope:.1f}). "
                        "Adversary may be adapting their approach."
                    ),
                    "evidence": {
                        "trend": [round(r, 1) for r in risk_trend],
                        "slope": round(slope, 1),
                    },
                })

        session_attack_types: List[str] = []
        for e in session_events:
            session_attack_types.extend(e.get("data", {}).get("attack_types", []))
        unique_types = list(set(session_attack_types))
        if len(unique_types) >= 3:
            coordinated = True
            insights.append({
                "type": "multi_vector_attack",
                "severity": "CRITICAL",
                "description": (
                    f"Multi-vector attack in session: {len(unique_types)} distinct attack types "
                    f"({', '.join(unique_types[:4])}). Sophisticated threat actor behavior."
                ),
                "evidence": {"attack_types": unique_types},
            })

        overall_severity = "INFO"
        for ins in insights:
            s = ins["severity"]
            if ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(s) > \
               ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(overall_severity):
                overall_severity = s

        correlation_score = min(100.0, len(insights) * 20 + (velocity * 5))

        return {
            "agent": self.name,
            "coordinated_attack": coordinated,
            "campaign_detected": campaign_detected,
            "correlation_score": round(correlation_score, 1),
            "severity": overall_severity,
            "insights": insights,
            "session_event_count": len(session_events),
            "global_velocity": velocity,
            "top_attack_patterns": dict(
                sorted(pattern_counts.items(), key=lambda x: -x[1])[:5]
            ),
            "risk_trend": [round(r, 1) for r in risk_trend],
        }
