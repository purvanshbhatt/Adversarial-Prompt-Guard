"""
Splunk HTTP Event Collector (HEC) simulation for AuroraSOC.

Stores events in memory (max 2000) and persists to a JSON file.
Each event uses Splunk's standard HEC envelope format.
"""

import json
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .mitre import map_attack_types
from .alerting import alert_engine
from .integrations.manager import integration_manager

MAX_EVENTS   = 2000
PERSIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "siem_events.json")
HOST         = "aurorasoc-01"
SOURCE       = "aurorasoc:detection"
SOURCETYPE   = "aurorasoc:prompt_injection"
INDEX        = "security"


class SIEMStore:
    def __init__(self):
        self._events: deque = deque(maxlen=MAX_EVENTS)
        self._load()

    # ── Ingestion ──────────────────────────────────────────────────────────────

    def ingest(self, hec_event: Dict) -> Dict:
        """Accept a Splunk HEC-formatted event dict, store it, run alerts."""
        hec_event["_id"] = str(uuid.uuid4())
        hec_event["_ts"] = hec_event.get("time", time.time())
        self._events.appendleft(hec_event)
        self._persist()
        alert_engine.check(hec_event)
        integration_manager.forward_all(hec_event)
        return hec_event

    def ingest_detection(self, prompt: str, detection: Dict, action: Optional[str] = None) -> Dict:
        """Build a Splunk HEC event from a detection result and ingest it."""
        hec = format_hec_event(prompt, detection, action)
        return self.ingest(hec)

    # ── Query ──────────────────────────────────────────────────────────────────

    def get_events(
        self,
        limit: int = 100,
        attack_type: Optional[str] = None,
        min_risk: Optional[float] = None,
        since_hours: Optional[float] = None,
    ) -> List[Dict]:
        events = list(self._events)
        if since_hours is not None:
            cutoff = time.time() - since_hours * 3600
            events = [e for e in events if e.get("_ts", 0) >= cutoff]
        if attack_type:
            events = [e for e in events if attack_type in e["event"].get("attack_types", [])]
        if min_risk is not None:
            events = [e for e in events if e["event"].get("risk_score", 0) >= min_risk]
        return events[:limit]

    def get_trends(self, hours: float = 24, bucket_minutes: int = 30) -> List[Dict]:
        """Return time-bucketed event counts for trend charts."""
        now    = time.time()
        cutoff = now - hours * 3600
        bucket_secs = bucket_minutes * 60
        buckets: Dict[int, int] = defaultdict(int)
        high_risk_buckets: Dict[int, int] = defaultdict(int)

        for ev in self._events:
            ts = ev.get("_ts", 0)
            if ts < cutoff:
                continue
            bk = int(ts // bucket_secs) * bucket_secs
            buckets[bk] += 1
            if ev["event"].get("risk_score", 0) > 75:
                high_risk_buckets[bk] += 1

        result = []
        cursor = int(cutoff // bucket_secs) * bucket_secs
        while cursor <= now:
            result.append({
                "timestamp": cursor,
                "datetime":  datetime.fromtimestamp(cursor, tz=timezone.utc).isoformat(),
                "label":     datetime.fromtimestamp(cursor, tz=timezone.utc).strftime("%H:%M"),
                "count":     buckets.get(cursor, 0),
                "high_risk": high_risk_buckets.get(cursor, 0),
            })
            cursor += bucket_secs
        return result

    def get_attack_timeline(self, hours: float = 24, bucket_minutes: int = 60) -> List[Dict]:
        """Return per-attack-type counts bucketed over time."""
        now    = time.time()
        cutoff = now - hours * 3600
        bucket_secs = bucket_minutes * 60

        type_buckets: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        all_times: set = set()

        for ev in self._events:
            ts = ev.get("_ts", 0)
            if ts < cutoff:
                continue
            bk = int(ts // bucket_secs) * bucket_secs
            all_times.add(bk)
            for atype in ev["event"].get("attack_types", []):
                type_buckets[atype][bk] += 1

        if not all_times:
            return []

        result = []
        for bk in sorted(all_times):
            row = {
                "timestamp": bk,
                "label":     datetime.fromtimestamp(bk, tz=timezone.utc).strftime("%H:%M"),
            }
            for atype, buckets in type_buckets.items():
                row[atype] = buckets.get(bk, 0)
            result.append(row)
        return result

    def get_attack_type_summary(self, hours: float = 24) -> Dict[str, int]:
        """Count occurrences of each attack type."""
        now    = time.time()
        cutoff = now - hours * 3600
        counts: Dict[str, int] = defaultdict(int)
        for ev in self._events:
            if ev.get("_ts", 0) < cutoff:
                continue
            for atype in ev["event"].get("attack_types", []):
                counts[atype] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def get_severity_summary(self, hours: float = 24) -> Dict[str, int]:
        now    = time.time()
        cutoff = now - hours * 3600
        counts: Dict[str, int] = defaultdict(int)
        for ev in self._events:
            if ev.get("_ts", 0) < cutoff:
                continue
            sev = ev["event"].get("severity", "LOW")
            counts[sev] += 1
        return dict(counts)

    def get_stats(self, hours: float = 24) -> Dict:
        now    = time.time()
        cutoff = now - hours * 3600
        recent = [e for e in self._events if e.get("_ts", 0) >= cutoff]
        scores = [e["event"].get("risk_score", 0) for e in recent]
        return {
            "total_events":   len(recent),
            "all_time":       len(self._events),
            "high_risk":      sum(1 for e in recent if e["event"].get("risk_score", 0) > 75),
            "critical":       sum(1 for e in recent if e["event"].get("risk_score", 0) > 90),
            "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "peak_risk":      round(max(scores), 1) if scores else 0,
            "attack_types":   self.get_attack_type_summary(hours),
            "severities":     self.get_severity_summary(hours),
        }

    def get_mitre_summary(self, hours: float = 24) -> List[Dict]:
        """MITRE TTP frequency across all recent events."""
        now    = time.time()
        cutoff = now - hours * 3600
        ttp_counts: Dict[str, Dict] = {}
        for ev in self._events:
            if ev.get("_ts", 0) < cutoff:
                continue
            for ttp in ev["event"].get("mitre_ttps", []):
                uid = ttp.get("sub") or ttp["id"]
                if uid not in ttp_counts:
                    ttp_counts[uid] = {**ttp, "count": 0}
                ttp_counts[uid]["count"] += 1
        return sorted(ttp_counts.values(), key=lambda x: x["count"], reverse=True)

    def get_spike_series(self, hours: float = 24) -> List[Dict]:
        """Return 15-min buckets of high-risk event counts (for spike chart)."""
        return self.get_trends(hours=hours, bucket_minutes=15)

    # ── Persistence ────────────────────────────────────────────────────────────

    def _persist(self):
        try:
            path = PERSIST_PATH
            os.makedirs(os.path.dirname(path), exist_ok=True)
            events = list(self._events)[:500]   # persist last 500
            with open(path, "w") as f:
                json.dump(events, f, default=str)
        except Exception:
            pass

    def _load(self):
        try:
            if os.path.exists(PERSIST_PATH):
                with open(PERSIST_PATH) as f:
                    events = json.load(f)
                for ev in reversed(events):
                    self._events.append(ev)
        except Exception:
            pass


def format_hec_event(prompt: str, detection: Dict[str, Any], action: Optional[str] = None) -> Dict:
    """Build a Splunk HEC-compatible event envelope from a detection result."""
    risk_score   = detection.get("risk_score", 0)
    attack_types = detection.get("attack_types", [])
    mitre_ttps   = map_attack_types(attack_types)

    severity_map = [
        (90, "CRITICAL"),
        (75, "HIGH"),
        (40, "MEDIUM"),
        (0,  "LOW"),
    ]
    severity = next((s for t, s in severity_map if risk_score >= t), "LOW")

    return {
        "time":       time.time(),
        "host":       HOST,
        "source":     SOURCE,
        "sourcetype": SOURCETYPE,
        "index":      INDEX,
        "event": {
            "timestamp":           datetime.now(tz=timezone.utc).isoformat(),
            "prompt":              prompt,
            "prompt_length":       len(prompt),
            "risk_score":          risk_score,
            "severity":            severity,
            "attack_types":        attack_types,
            "action":              action or "DETECT",
            "rule_based_score":    detection.get("rule_based_score", 0),
            "ml_score":            detection.get("ml_score", 0),
            "semantic_score":      detection.get("semantic_score", 0),
            "suspicious_tokens":   detection.get("suspicious_tokens", []),
            "obfuscation_techniques": detection.get("obfuscation_techniques", []),
            "explanation":         detection.get("explanation", ""),
            "mitre_ttps":          mitre_ttps,
            "platform":            "AuroraSOC",
            "version":             "2.0",
        },
    }


# Singleton
siem_store = SIEMStore()
