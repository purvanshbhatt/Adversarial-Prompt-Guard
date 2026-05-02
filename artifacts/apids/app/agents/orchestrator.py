import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from .adversary_simulation_agent import AdversarySimulationAgent
from .forensics_agent import ForensicsAgent
from .prompt_security_agent import PromptSecurityAgent
from .risk_scoring_agent import RiskScoringAgent
from .shared_memory import EventStore, SecurityEvent
from .threat_correlation_agent import ThreatCorrelationAgent


class SOCOrchestrator:
    def __init__(self, run_analysis_fn: Callable, generate_attacks_fn: Callable):
        self.prompt_agent = PromptSecurityAgent(run_analysis_fn)
        self.correlation_agent = ThreatCorrelationAgent()
        self.risk_agent = RiskScoringAgent()
        self.forensics_agent = ForensicsAgent()
        self.simulation_agent = AdversarySimulationAgent(generate_attacks_fn, run_analysis_fn)

    def analyze(self, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        if not session_id:
            session_id = f"sess-{uuid.uuid4().hex[:8]}"

        prompt_result = self.prompt_agent.process(prompt)
        correlation_result = self.correlation_agent.process(
            session_id=session_id,
            current_event_data=prompt_result,
        )
        risk_result = self.risk_agent.process(
            prompt_result=prompt_result,
            correlation_result=correlation_result,
            session_id=session_id,
        )

        enterprise_score = risk_result["enterprise_risk_score"]
        severity = prompt_result["severity"]
        if risk_result["risk_level"] in ("CRITICAL", "HIGH"):
            severity = risk_result["risk_level"]

        event = SecurityEvent.new(
            agent="orchestrator",
            event_type="soc_analysis",
            severity=severity,
            prompt=prompt,
            session_id=session_id,
            enterprise_risk_score=enterprise_score,
            data={
                **prompt_result,
                "correlation": correlation_result,
                "risk_scoring": risk_result,
            },
            tags=(
                ["malicious"] if prompt_result["is_malicious"] else []
            ) + (
                ["coordinated"] if correlation_result["coordinated_attack"] else []
            ),
        )
        forensics_result = self.forensics_agent.process(event)

        verdict_map = {
            "CRITICAL": "🔴 CRITICAL THREAT",
            "HIGH": "🟠 HIGH RISK",
            "MEDIUM": "🟡 SUSPICIOUS",
            "LOW": "🔵 LOW RISK",
            "SAFE": "🟢 SAFE",
        }

        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "session_id": session_id,
            "verdict": verdict_map.get(risk_result["risk_level"], risk_result["risk_level"]),
            "risk_level": risk_result["risk_level"],
            "enterprise_risk_score": enterprise_score,
            "recommended_action": risk_result["recommended_action"],
            "agents": {
                "prompt_security": prompt_result,
                "threat_correlation": correlation_result,
                "risk_scoring": risk_result,
                "forensics": forensics_result,
            },
            "correlation_insights": correlation_result.get("insights", []),
            "coordinated_attack": correlation_result["coordinated_attack"],
        }

    def correlate(self) -> Dict[str, Any]:
        store = EventStore.get()
        pattern_counts = store.get_attack_pattern_counts(window_seconds=3600)
        recent = store.get_recent_events(window_seconds=300)
        stats = store.get_stats()

        velocity = len(recent)
        top_sessions: Dict[str, int] = {}
        for e in recent:
            sid = e.get("session_id", "unknown")
            top_sessions[sid] = top_sessions.get(sid, 0) + 1
        top_sessions_sorted = dict(
            sorted(top_sessions.items(), key=lambda x: -x[1])[:5]
        )

        attack_breakdown: Dict[str, int] = {}
        for e in store.get_events(limit=500):
            for at in e.get("data", {}).get("attack_types", []):
                attack_breakdown[at] = attack_breakdown.get(at, 0) + 1

        return {
            "global_stats": stats,
            "current_velocity": velocity,
            "top_active_sessions": top_sessions_sorted,
            "attack_pattern_counts_1h": pattern_counts,
            "attack_type_breakdown_all": attack_breakdown,
            "threat_level": (
                "CRITICAL" if velocity >= 10 else
                "HIGH" if velocity >= 5 else
                "MEDIUM" if velocity >= 2 else
                "LOW"
            ),
        }

    def simulate(
        self,
        strategy: str = "all",
        n: int = 8,
        goal: str = "bypass safety restrictions",
    ) -> Dict[str, Any]:
        result = self.simulation_agent.process(
            strategy=strategy,
            n=n,
            goal=goal,
            feed_to_detection=True,
        )

        store = EventStore.get()
        session_id = f"sim-{uuid.uuid4().hex[:8]}"

        for dr in result.get("detection_results", []):
            event = SecurityEvent.new(
                agent="adversary_simulation",
                event_type="simulation",
                severity="HIGH" if dr["is_malicious"] else "LOW",
                prompt=dr["prompt"],
                session_id=session_id,
                enterprise_risk_score=dr["risk_score"],
                data=dr,
                tags=["simulation", dr["strategy"]],
            )
            store.add(event)

        return {
            **result,
            "simulation_session_id": session_id,
            "message": (
                f"Simulated {result['total_attacks']} adversarial attacks. "
                f"Detection rate: {result['robustness_score']:.1f}%. "
                f"Results stored in forensics with session_id={session_id}."
            ),
        }

    def get_report(self, session_id: Optional[str] = None) -> str:
        return self.forensics_agent.get_investigation_report(session_id=session_id)

    def get_timeline(self, limit: int = 50) -> Dict[str, Any]:
        timeline = self.forensics_agent.get_timeline(limit=limit)
        store = EventStore.get()
        return {
            "timeline": timeline,
            "total": store.get_stats()["total_events"],
        }

    def agents_status(self) -> Dict[str, Any]:
        return {
            "agents": [
                self.prompt_agent.status(),
                self.correlation_agent.status(),
                self.risk_agent.status(),
                self.simulation_agent.status(),
                self.forensics_agent.status(),
            ],
            "platform": "AuroraSOC",
            "version": "2.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
