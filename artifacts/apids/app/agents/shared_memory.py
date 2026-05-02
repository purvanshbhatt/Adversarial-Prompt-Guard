import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

STORE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../data/soc_events.json")
)

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    session_id: str
    agent: str
    event_type: str
    severity: str
    prompt: str
    data: Dict[str, Any]
    enterprise_risk_score: float = 0.0
    tags: List[str] = field(default_factory=list)

    @staticmethod
    def new(
        agent: str,
        event_type: str,
        severity: str,
        prompt: str,
        data: Dict[str, Any],
        session_id: Optional[str] = None,
        enterprise_risk_score: float = 0.0,
        tags: Optional[List[str]] = None,
    ) -> "SecurityEvent":
        return SecurityEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=session_id or f"sess-{uuid.uuid4().hex[:8]}",
            agent=agent,
            event_type=event_type,
            severity=severity,
            prompt=prompt[:500],
            data=data,
            enterprise_risk_score=enterprise_risk_score,
            tags=tags or [],
        )


class EventStore:
    _instance: Optional["EventStore"] = None

    def __init__(self) -> None:
        self._events: List[Dict] = []
        self._load()

    @classmethod
    def get(cls) -> "EventStore":
        if cls._instance is None:
            cls._instance = EventStore()
        return cls._instance

    def add(self, event: SecurityEvent) -> None:
        self._events.append(asdict(event))
        if len(self._events) > 1000:
            self._events = self._events[-1000:]
        self._persist()

    def get_events(
        self,
        limit: int = 50,
        session_id: Optional[str] = None,
        min_severity: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> List[Dict]:
        events = list(self._events)
        if session_id:
            events = [e for e in events if e.get("session_id") == session_id]
        if min_severity and min_severity in SEVERITY_ORDER:
            min_idx = SEVERITY_ORDER.index(min_severity)
            events = [
                e for e in events
                if SEVERITY_ORDER.index(e.get("severity", "INFO")) >= min_idx
            ]
        if agent:
            events = [e for e in events if e.get("agent") == agent]
        return list(reversed(events))[:limit]

    def get_timeline(self, limit: int = 100) -> List[Dict]:
        return list(reversed(self._events))[:limit]

    def get_recent_events(self, window_seconds: int = 300) -> List[Dict]:
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        return [e for e in self._events if self._ts_epoch(e.get("timestamp", "")) > cutoff]

    def get_session_events(self, session_id: str, window_seconds: int = 600) -> List[Dict]:
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        return [
            e for e in self._events
            if e.get("session_id") == session_id
            and self._ts_epoch(e.get("timestamp", "")) > cutoff
        ]

    def get_attack_pattern_counts(self, window_seconds: int = 3600) -> Dict[str, int]:
        recent = self.get_recent_events(window_seconds)
        counts: Dict[str, int] = {}
        for e in recent:
            for at in e.get("data", {}).get("attack_types", []):
                counts[at] = counts.get(at, 0) + 1
        return counts

    def get_session_risk_trend(self, session_id: str) -> List[float]:
        events = [
            e for e in self._events
            if e.get("session_id") == session_id
        ]
        return [e.get("enterprise_risk_score", 0.0) for e in events[-10:]]

    def get_stats(self) -> Dict:
        total = len(self._events)
        malicious = sum(1 for e in self._events if e.get("data", {}).get("is_malicious"))
        critical = sum(1 for e in self._events if e.get("severity") == "CRITICAL")
        high = sum(1 for e in self._events if e.get("severity") == "HIGH")
        agents_seen = list({e.get("agent", "") for e in self._events if e.get("agent")})
        return {
            "total_events": total,
            "malicious_events": malicious,
            "critical_events": critical,
            "high_events": high,
            "agents_active": agents_seen,
        }

    def clear(self) -> None:
        self._events = []
        self._persist()

    def _ts_epoch(self, ts: str) -> float:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    def _persist(self) -> None:
        try:
            os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
            with open(STORE_PATH, "w") as f:
                json.dump(self._events, f, indent=2)
        except Exception:
            pass

    def _load(self) -> None:
        try:
            if os.path.exists(STORE_PATH):
                with open(STORE_PATH) as f:
                    self._events = json.load(f)
        except Exception:
            self._events = []
