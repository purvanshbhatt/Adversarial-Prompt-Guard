"""
Cross-agent message bus for AuroraSOC.

Agents publish structured messages to the bus; the dashboard reads them to show
the live inter-agent communication feed and lifecycle trace.

Message types:
  DETECTION_RESULT   — Prompt Security → Correlation / Risk Scoring
  CORRELATION_UPDATE — Correlation → Risk Scoring / Forensics
  RISK_VERDICT       — Risk Scoring → Orchestrator / SIEM
  ALERT_RAISED       — any agent → SIEM / Orchestrator
  MITIGATION_ACTION  — Orchestrator → Mitigation Engine
  LIFECYCLE_EVENT    — Orchestrator → all agents (injection→bypass→detect→log)
  FORENSICS_STORED   — Forensics → broadcast
  SIEM_FORWARDED     — SIEM Agent → broadcast
  ELASTIC_INDEXED    — Elastic Pipeline → broadcast
  ADVERSARY_ATTACK   — Adversary Agent → Orchestrator
  BYPASS_DETECTED    — Adversary Agent → Correlation / SIEM
"""

import time
import uuid
from collections import deque
from typing import Dict, List, Optional

MAX_MESSAGES = 500

AGENT_COLORS = {
    "prompt_security":      "#58a6ff",
    "threat_correlation":   "#d29922",
    "risk_scoring":         "#f85149",
    "adversary":            "#a371f7",
    "forensics":            "#3fb950",
    "siem":                 "#e3b341",
    "elastic":              "#f472b6",
    "orchestrator":         "#c9d1d9",
    "mitigation":           "#34d399",
    "lifecycle":            "#fb923c",
}

AGENT_ICONS = {
    "prompt_security":      "🔍",
    "threat_correlation":   "🤝",
    "risk_scoring":         "📊",
    "adversary":            "⚔️",
    "forensics":            "🔬",
    "siem":                 "📡",
    "elastic":              "🔎",
    "orchestrator":         "🎛️",
    "mitigation":           "🛡️",
    "lifecycle":            "🔄",
}

MSG_TYPE_COLORS = {
    "DETECTION_RESULT":   "#58a6ff",
    "CORRELATION_UPDATE": "#d29922",
    "RISK_VERDICT":       "#f85149",
    "ALERT_RAISED":       "#f85149",
    "MITIGATION_ACTION":  "#3fb950",
    "LIFECYCLE_EVENT":    "#fb923c",
    "FORENSICS_STORED":   "#3fb950",
    "SIEM_FORWARDED":     "#e3b341",
    "ELASTIC_INDEXED":    "#f472b6",
    "ADVERSARY_ATTACK":   "#a371f7",
    "BYPASS_DETECTED":    "#f85149",
}


class AgentMessage:
    __slots__ = ("id", "timestamp", "sender", "receiver", "msg_type",
                 "payload", "session_id", "severity")

    def __init__(self, sender: str, receiver: str, msg_type: str,
                 payload: Dict, session_id: str = "", severity: str = "INFO"):
        self.id         = str(uuid.uuid4())[:8]
        self.timestamp  = time.time()
        self.sender     = sender
        self.receiver   = receiver
        self.msg_type   = msg_type
        self.payload    = payload
        self.session_id = session_id
        self.severity   = severity

    def to_dict(self) -> Dict:
        return {
            "id":         self.id,
            "timestamp":  self.timestamp,
            "sender":     self.sender,
            "receiver":   self.receiver,
            "msg_type":   self.msg_type,
            "payload":    self.payload,
            "session_id": self.session_id,
            "severity":   self.severity,
            "sender_color": AGENT_COLORS.get(self.sender, "#8b949e"),
            "sender_icon":  AGENT_ICONS.get(self.sender, "🤖"),
            "type_color":   MSG_TYPE_COLORS.get(self.msg_type, "#8b949e"),
        }


class MessageBus:
    _instance: Optional["MessageBus"] = None

    def __init__(self):
        self._messages: deque = deque(maxlen=MAX_MESSAGES)
        self._agent_stats: Dict[str, Dict] = {}

    @classmethod
    def get(cls) -> "MessageBus":
        if cls._instance is None:
            cls._instance = MessageBus()
        return cls._instance

    def publish(
        self,
        sender:     str,
        receiver:   str,
        msg_type:   str,
        payload:    Dict,
        session_id: str = "",
        severity:   str = "INFO",
    ) -> Dict:
        msg = AgentMessage(sender, receiver, msg_type, payload, session_id, severity)
        self._messages.appendleft(msg)
        # Update agent stats
        self._agent_stats.setdefault(sender, {"sent": 0, "last_active": 0})
        self._agent_stats[sender]["sent"]        += 1
        self._agent_stats[sender]["last_active"]  = msg.timestamp
        return msg.to_dict()

    def get_messages(
        self,
        limit:      int = 50,
        agent:      Optional[str] = None,
        msg_type:   Optional[str] = None,
        session_id: Optional[str] = None,
        since:      Optional[float] = None,
    ) -> List[Dict]:
        msgs = [m for m in self._messages]
        if agent:
            msgs = [m for m in msgs if m.sender == agent or m.receiver in (agent, "broadcast")]
        if msg_type:
            msgs = [m for m in msgs if m.msg_type == msg_type]
        if session_id:
            msgs = [m for m in msgs if m.session_id == session_id]
        if since:
            msgs = [m for m in msgs if m.timestamp >= since]
        return [m.to_dict() for m in msgs[:limit]]

    def get_stats(self) -> Dict:
        msgs = list(self._messages)
        by_type: Dict[str, int] = {}
        by_agent: Dict[str, int] = {}
        for m in msgs:
            by_type[m.msg_type]  = by_type.get(m.msg_type, 0) + 1
            by_agent[m.sender]   = by_agent.get(m.sender, 0) + 1
        return {
            "total_messages":  len(msgs),
            "by_type":         by_type,
            "by_agent":        by_agent,
            "agent_stats":     self._agent_stats,
            "active_agents":   len(self._agent_stats),
        }

    def get_lifecycle_trace(self, session_id: str) -> List[Dict]:
        """Return ordered messages for a specific lifecycle session."""
        msgs = [m for m in self._messages if m.session_id == session_id]
        return [m.to_dict() for m in sorted(msgs, key=lambda m: m.timestamp)]

    def clear(self):
        self._messages.clear()
        self._agent_stats.clear()


# Singleton
message_bus = MessageBus.get()


# ── Convenience publishers ────────────────────────────────────────────────────

def publish_detection(prompt: str, result: Dict, session_id: str = "") -> Dict:
    risk = result.get("risk_score", 0)
    return message_bus.publish(
        sender     = "prompt_security",
        receiver   = "threat_correlation",
        msg_type   = "DETECTION_RESULT",
        payload    = {
            "risk_score":   risk,
            "is_malicious": result.get("is_malicious", False),
            "attack_types": result.get("attack_types", []),
            "prompt":       prompt[:80],
        },
        session_id = session_id,
        severity   = "HIGH" if risk > 75 else "MEDIUM" if risk > 40 else "INFO",
    )


def publish_risk_verdict(risk_score: float, verdict: str, action: str, session_id: str = "") -> Dict:
    return message_bus.publish(
        sender     = "risk_scoring",
        receiver   = "orchestrator",
        msg_type   = "RISK_VERDICT",
        payload    = {"enterprise_risk_score": risk_score, "verdict": verdict, "action": action},
        session_id = session_id,
        severity   = "CRITICAL" if risk_score > 90 else "HIGH" if risk_score > 70 else "INFO",
    )


def publish_alert(sender: str, message: str, risk_score: float, session_id: str = "") -> Dict:
    return message_bus.publish(
        sender     = sender,
        receiver   = "siem",
        msg_type   = "ALERT_RAISED",
        payload    = {"message": message, "risk_score": risk_score},
        session_id = session_id,
        severity   = "CRITICAL" if risk_score > 90 else "HIGH",
    )


def publish_lifecycle_event(stage: str, detail: str, session_id: str = "", extra: Dict = None) -> Dict:
    return message_bus.publish(
        sender     = "lifecycle",
        receiver   = "broadcast",
        msg_type   = "LIFECYCLE_EVENT",
        payload    = {"stage": stage, "detail": detail, **(extra or {})},
        session_id = session_id,
        severity   = "HIGH" if stage in ("bypass", "alert") else "INFO",
    )


def publish_bypass(prompt: str, risk_score: float, mutation_strategy: str, session_id: str = "") -> Dict:
    return message_bus.publish(
        sender     = "adversary",
        receiver   = "siem",
        msg_type   = "BYPASS_DETECTED",
        payload    = {
            "prompt":            prompt[:80],
            "risk_score":        risk_score,
            "mutation_strategy": mutation_strategy,
        },
        session_id = session_id,
        severity   = "CRITICAL",
    )


def publish_elastic_indexed(doc_id: str, risk_score: float, event_type: str, session_id: str = "") -> Dict:
    return message_bus.publish(
        sender     = "elastic",
        receiver   = "broadcast",
        msg_type   = "ELASTIC_INDEXED",
        payload    = {"doc_id": doc_id, "risk_score": risk_score, "event_type": event_type},
        session_id = session_id,
        severity   = "INFO",
    )
