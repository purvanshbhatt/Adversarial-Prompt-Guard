"""
Alert engine for AuroraSOC SIEM.

Rules evaluated on every ingested event:
  1. HIGH_RISK    — risk_score > 75
  2. CRITICAL     — risk_score > 90
  3. SPIKE        — 5+ high-risk events in 10 minutes
  4. REPEATED     — same attack type 3+ times in 5 minutes
"""

import uuid
import time
from collections import defaultdict, deque
from typing import List, Dict, Optional

MAX_ALERTS = 500

SEVERITY_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#d29922",
    "MEDIUM":   "#58a6ff",
    "INFO":     "#8b949e",
}

RULE_LABELS = {
    "HIGH_RISK":  "High Risk Prompt",
    "CRITICAL":   "Critical Threat",
    "SPIKE":      "Attack Spike Detected",
    "REPEATED":   "Repeated Attack Pattern",
}


class AlertEngine:
    def __init__(self):
        self._alerts: deque = deque(maxlen=MAX_ALERTS)
        self._recent_high_risk: deque = deque()          # (timestamp,)
        self._recent_by_type: Dict[str, deque] = defaultdict(lambda: deque())

    def check(self, event: Dict) -> List[Dict]:
        """
        Evaluate all alert rules against a new SIEM event.
        Returns list of generated alerts (may be empty).
        """
        now        = event.get("_ts", time.time())
        risk_score = event["event"].get("risk_score", 0)
        attack_types = event["event"].get("attack_types", [])
        severity   = event["event"].get("severity", "LOW")
        prompt_preview = event["event"].get("prompt", "")[:120]
        new_alerts: List[Dict] = []

        # ── Rule 1: CRITICAL ──────────────────────────────────────────────────
        if risk_score > 90:
            new_alerts.append(self._make_alert(
                rule     = "CRITICAL",
                severity = "CRITICAL",
                message  = f"Critical threat detected — risk score {risk_score}",
                detail   = f"Attack types: {', '.join(attack_types)}",
                preview  = prompt_preview,
                risk     = risk_score,
                attack_types = attack_types,
                ts       = now,
            ))
        # ── Rule 2: HIGH_RISK ─────────────────────────────────────────────────
        elif risk_score > 75:
            new_alerts.append(self._make_alert(
                rule     = "HIGH_RISK",
                severity = "HIGH",
                message  = f"High-risk prompt detected — score {risk_score}",
                detail   = f"Severity: {severity} | Types: {', '.join(attack_types)}",
                preview  = prompt_preview,
                risk     = risk_score,
                attack_types = attack_types,
                ts       = now,
            ))

        # Track high-risk events for spike detection
        if risk_score > 75:
            self._recent_high_risk.append(now)

        # ── Rule 3: SPIKE ─────────────────────────────────────────────────────
        window = 10 * 60  # 10 minutes
        cutoff = now - window
        while self._recent_high_risk and self._recent_high_risk[0] < cutoff:
            self._recent_high_risk.popleft()
        if len(self._recent_high_risk) >= 5:
            # Only fire spike alert if we haven't fired one in the last 5 min
            if not self._recent_spike_alert(now):
                new_alerts.append(self._make_alert(
                    rule     = "SPIKE",
                    severity = "CRITICAL",
                    message  = f"Attack spike — {len(self._recent_high_risk)} high-risk events in 10 min",
                    detail   = "Possible coordinated attack or automated scanning in progress.",
                    preview  = prompt_preview,
                    risk     = risk_score,
                    attack_types = attack_types,
                    ts       = now,
                ))

        # ── Rule 4: REPEATED ──────────────────────────────────────────────────
        type_window = 5 * 60  # 5 minutes
        type_cutoff = now - type_window
        for atype in attack_types:
            q = self._recent_by_type[atype]
            q.append(now)
            while q and q[0] < type_cutoff:
                q.popleft()
            if len(q) >= 3 and not self._recent_repeat_alert(atype, now):
                new_alerts.append(self._make_alert(
                    rule     = "REPEATED",
                    severity = "HIGH",
                    message  = f"Repeated {atype.replace('_', ' ').title()} attacks — {len(q)}× in 5 min",
                    detail   = f"Attack pattern '{atype}' is recurring. Possible automated probe.",
                    preview  = prompt_preview,
                    risk     = risk_score,
                    attack_types = [atype],
                    ts       = now,
                    extra    = {"attack_type": atype, "count": len(q)},
                ))

        for alert in new_alerts:
            self._alerts.appendleft(alert)

        return new_alerts

    def get_alerts(self, limit: int = 50, active_only: bool = False) -> List[Dict]:
        alerts = list(self._alerts)
        if active_only:
            alerts = [a for a in alerts if not a.get("dismissed")]
        return alerts[:limit]

    def dismiss(self, alert_id: str) -> bool:
        for alert in self._alerts:
            if alert["id"] == alert_id:
                alert["dismissed"] = True
                return True
        return False

    def get_stats(self) -> Dict:
        alerts = list(self._alerts)
        active = [a for a in alerts if not a.get("dismissed")]
        return {
            "total":    len(alerts),
            "active":   len(active),
            "critical": sum(1 for a in active if a["severity"] == "CRITICAL"),
            "high":     sum(1 for a in active if a["severity"] == "HIGH"),
            "by_rule":  {
                rule: sum(1 for a in active if a["rule"] == rule)
                for rule in ["CRITICAL", "HIGH_RISK", "SPIKE", "REPEATED"]
            },
        }

    def _make_alert(self, rule, severity, message, detail, preview, risk, attack_types, ts, extra=None) -> Dict:
        return {
            "id":           str(uuid.uuid4()),
            "rule":         rule,
            "label":        RULE_LABELS.get(rule, rule),
            "severity":     severity,
            "color":        SEVERITY_COLOR.get(severity, "#8b949e"),
            "message":      message,
            "detail":       detail,
            "prompt_preview": preview,
            "risk_score":   risk,
            "attack_types": attack_types,
            "timestamp":    ts,
            "dismissed":    False,
            **(extra or {}),
        }

    def _recent_spike_alert(self, now: float) -> bool:
        for a in self._alerts:
            if a["rule"] == "SPIKE" and (now - a["timestamp"]) < 300:
                return True
        return False

    def _recent_repeat_alert(self, atype: str, now: float) -> bool:
        for a in self._alerts:
            if a["rule"] == "REPEATED" and a.get("attack_type") == atype and (now - a["timestamp"]) < 300:
                return True
        return False


# Singleton
alert_engine = AlertEngine()
