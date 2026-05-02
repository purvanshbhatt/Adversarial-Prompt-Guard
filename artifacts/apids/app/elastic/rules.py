"""
Elastic Security detection rules engine.

Rules (matching Elastic's EQL / threshold rule patterns):
  1. REPEATED_INJECTION  — same attack category 3+ times in 5 min
  2. OBFUSCATION_BURST   — 2+ obfuscated prompts in 5 min
  3. HIGH_RISK_SPIKE     — 3+ events with risk > 75 in 10 min
  4. JAILBREAK_DETECTED  — any jailbreak attempt → immediate alert
  5. DATA_EXFIL_ATTEMPT  — data_exfiltration category detected
  6. TOKEN_MANIPULATION  — token manipulation / encoding obfuscation
"""

import time
import uuid
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

MAX_RULE_ALERTS = 500

RULE_SEVERITY = {
    "REPEATED_INJECTION": "high",
    "OBFUSCATION_BURST":  "medium",
    "HIGH_RISK_SPIKE":    "critical",
    "JAILBREAK_DETECTED": "high",
    "DATA_EXFIL_ATTEMPT": "high",
    "TOKEN_MANIPULATION": "medium",
}

RULE_META = {
    "REPEATED_INJECTION": {
        "name":        "Repeated Prompt Injection Attempts",
        "description": "Detects repeated prompt injection attempts from the same source within a short window.",
        "type":        "threshold",
        "query":       "event_type:(prompt_injection OR jailbreak OR instruction_override)",
        "threshold":   3,
        "window":      "5m",
        "tags":        ["prompt-injection", "threshold", "repeated-attack"],
        "mitre":       ["T1190", "T1059"],
    },
    "OBFUSCATION_BURST": {
        "name":        "Obfuscation Pattern Detected",
        "description": "Multiple prompts with encoding or Unicode obfuscation techniques in rapid succession.",
        "type":        "threshold",
        "query":       "obfuscation_type:*",
        "threshold":   2,
        "window":      "5m",
        "tags":        ["obfuscation", "evasion", "encoding"],
        "mitre":       ["T1027", "T1027.002"],
    },
    "HIGH_RISK_SPIKE": {
        "name":        "High-Risk Prompt Spike",
        "description": "Sudden increase in high-risk (score > 75) prompt injection events — possible automated attack.",
        "type":        "threshold",
        "query":       "risk_score:>75",
        "threshold":   3,
        "window":      "10m",
        "tags":        ["spike", "high-risk", "automated"],
        "mitre":       ["T1190"],
    },
    "JAILBREAK_DETECTED": {
        "name":        "Jailbreak Attempt Detected",
        "description": "Prompt classified as a jailbreak attempt (DAN, character override, no-restrictions framing).",
        "type":        "match",
        "query":       "attack_category:jailbreak",
        "threshold":   1,
        "window":      "1m",
        "tags":        ["jailbreak", "alignment-bypass", "immediate"],
        "mitre":       ["T1566.001", "T1204.002"],
    },
    "DATA_EXFIL_ATTEMPT": {
        "name":        "Data Exfiltration Attempt",
        "description": "Prompt attempts to extract system prompt, model config, or internal data.",
        "type":        "match",
        "query":       "attack_category:data_exfiltration",
        "threshold":   1,
        "window":      "1m",
        "tags":        ["data-exfiltration", "system-prompt", "collection"],
        "mitre":       ["T1567", "T1213"],
    },
    "TOKEN_MANIPULATION": {
        "name":        "Token Manipulation / Encoding Evasion",
        "description": "Detected base64, URL-encoding, Unicode padding, or token-splitting to evade detection.",
        "type":        "match",
        "query":       "event_type:obfuscation OR obfuscation_type:*",
        "threshold":   1,
        "window":      "1m",
        "tags":        ["token-manipulation", "obfuscation", "evasion"],
        "mitre":       ["T1027"],
    },
}


class RuleAlert:
    __slots__ = ("id", "rule_id", "severity", "message", "detail",
                 "doc_ids", "timestamp", "dismissed", "risk_score",
                 "attack_types", "prompt_preview")

    def __init__(self, rule_id: str, severity: str, message: str, detail: str,
                 doc_ids: List[str], risk_score: float, attack_types: List[str],
                 prompt_preview: str = ""):
        self.id            = str(uuid.uuid4())
        self.rule_id       = rule_id
        self.severity      = severity
        self.message       = message
        self.detail        = detail
        self.doc_ids       = doc_ids
        self.timestamp     = time.time()
        self.dismissed     = False
        self.risk_score    = risk_score
        self.attack_types  = attack_types
        self.prompt_preview = prompt_preview

    def to_dict(self) -> Dict:
        return {
            "id":             self.id,
            "rule_id":        self.rule_id,
            "rule_name":      RULE_META.get(self.rule_id, {}).get("name", self.rule_id),
            "severity":       self.severity,
            "message":        self.message,
            "detail":         self.detail,
            "doc_count":      len(self.doc_ids),
            "timestamp":      self.timestamp,
            "dismissed":      self.dismissed,
            "risk_score":     self.risk_score,
            "attack_types":   self.attack_types,
            "prompt_preview": self.prompt_preview,
            "tags":           RULE_META.get(self.rule_id, {}).get("tags", []),
            "mitre":          RULE_META.get(self.rule_id, {}).get("mitre", []),
        }


class DetectionRulesEngine:
    def __init__(self):
        self._alerts: deque = deque(maxlen=MAX_RULE_ALERTS)

        # Per-rule tracking windows
        self._repeated_window:  deque = deque()   # (ts, attack_category)
        self._obf_window:       deque = deque()   # (ts,)
        self._high_risk_window: deque = deque()   # (ts,)
        # Dedup: track last alert time per rule
        self._last_alert: Dict[str, float] = {}

    def evaluate(self, doc: Dict) -> List[Dict]:
        """Evaluate all rules against a new indexed document."""
        now    = doc.get("_ts", time.time())
        alerts: List[RuleAlert] = []

        risk       = doc.get("risk_score", 0)
        attack_cat = doc.get("attack_category", "")
        atypes     = doc.get("attack_categories", [])
        obf_type   = doc.get("obfuscation_type", "")
        ev_type    = doc.get("event_type", "")
        preview    = doc.get("prompt", "")[:120]
        doc_id     = doc.get("_id", "")

        # ── Rule: JAILBREAK_DETECTED (match, fires immediately) ───────────────
        if attack_cat == "jailbreak" or "jailbreak" in atypes:
            if self._can_fire("JAILBREAK_DETECTED", now, cooldown=60):
                alerts.append(RuleAlert(
                    rule_id    = "JAILBREAK_DETECTED",
                    severity   = "high",
                    message    = "Jailbreak attempt detected",
                    detail     = f"Prompt classified as jailbreak. Risk: {risk}. Tokens: {doc.get('suspicious_tokens', [])}",
                    doc_ids    = [doc_id],
                    risk_score = risk,
                    attack_types = atypes,
                    prompt_preview = preview,
                ))

        # ── Rule: DATA_EXFIL_ATTEMPT ──────────────────────────────────────────
        if attack_cat == "data_exfiltration" or "data_exfiltration" in atypes:
            if self._can_fire("DATA_EXFIL_ATTEMPT", now, cooldown=60):
                alerts.append(RuleAlert(
                    rule_id    = "DATA_EXFIL_ATTEMPT",
                    severity   = "high",
                    message    = "Data exfiltration attempt detected",
                    detail     = f"Prompt attempting to extract system context. Risk: {risk}.",
                    doc_ids    = [doc_id],
                    risk_score = risk,
                    attack_types = atypes,
                    prompt_preview = preview,
                ))

        # ── Rule: TOKEN_MANIPULATION ──────────────────────────────────────────
        if obf_type or ev_type == "obfuscation":
            if self._can_fire("TOKEN_MANIPULATION", now, cooldown=120):
                alerts.append(RuleAlert(
                    rule_id    = "TOKEN_MANIPULATION",
                    severity   = "medium",
                    message    = f"Token manipulation / obfuscation detected: {obf_type or ev_type}",
                    detail     = f"Techniques: {doc.get('obfuscation_types', [])}. Risk: {risk}.",
                    doc_ids    = [doc_id],
                    risk_score = risk,
                    attack_types = atypes,
                    prompt_preview = preview,
                ))

        # ── Rule: REPEATED_INJECTION (threshold, 3 in 5 min) ─────────────────
        if attack_cat:
            self._repeated_window.append((now, attack_cat))
        cutoff_5m = now - 300
        while self._repeated_window and self._repeated_window[0][0] < cutoff_5m:
            self._repeated_window.popleft()
        # Count by category
        cat_counts: Dict[str, int] = {}
        cat_docs:   Dict[str, List[str]] = {}
        for ts, cat in self._repeated_window:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_docs.setdefault(cat, []).append(doc_id)
        for cat, cnt in cat_counts.items():
            if cnt >= 3 and self._can_fire(f"REPEATED_INJECTION_{cat}", now, cooldown=300):
                alerts.append(RuleAlert(
                    rule_id    = "REPEATED_INJECTION",
                    severity   = "high",
                    message    = f"Repeated {cat.replace('_',' ').title()} attempts — {cnt}× in 5 min",
                    detail     = f"Attack pattern '{cat}' is recurring. Possible automated probe or scanner.",
                    doc_ids    = cat_docs.get(cat, [doc_id]),
                    risk_score = risk,
                    attack_types = [cat],
                    prompt_preview = preview,
                ))

        # ── Rule: OBFUSCATION_BURST (threshold, 2 in 5 min) ──────────────────
        if obf_type:
            self._obf_window.append(now)
        while self._obf_window and self._obf_window[0] < cutoff_5m:
            self._obf_window.popleft()
        if len(self._obf_window) >= 2 and self._can_fire("OBFUSCATION_BURST", now, cooldown=300):
            alerts.append(RuleAlert(
                rule_id    = "OBFUSCATION_BURST",
                severity   = "medium",
                message    = f"Obfuscation burst — {len(self._obf_window)} encoded prompts in 5 min",
                detail     = "Multiple prompts using encoding/Unicode evasion techniques detected.",
                doc_ids    = [doc_id],
                risk_score = risk,
                attack_types = atypes,
                prompt_preview = preview,
            ))

        # ── Rule: HIGH_RISK_SPIKE (threshold, 3 in 10 min) ───────────────────
        if risk > 75:
            self._high_risk_window.append(now)
        cutoff_10m = now - 600
        while self._high_risk_window and self._high_risk_window[0] < cutoff_10m:
            self._high_risk_window.popleft()
        if len(self._high_risk_window) >= 3 and self._can_fire("HIGH_RISK_SPIKE", now, cooldown=600):
            alerts.append(RuleAlert(
                rule_id    = "HIGH_RISK_SPIKE",
                severity   = "critical",
                message    = f"High-risk spike — {len(self._high_risk_window)} events (risk>75) in 10 min",
                detail     = "Sustained high-risk activity. May indicate automated attack or lateral expansion.",
                doc_ids    = [doc_id],
                risk_score = risk,
                attack_types = atypes,
                prompt_preview = preview,
            ))

        for alert in alerts:
            self._alerts.appendleft(alert)

        return [a.to_dict() for a in alerts]

    def get_alerts(self, limit: int = 50, active_only: bool = False) -> List[Dict]:
        alerts = list(self._alerts)
        if active_only:
            alerts = [a for a in alerts if not a.dismissed]
        return [a.to_dict() for a in alerts[:limit]]

    def dismiss(self, alert_id: str) -> bool:
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.dismissed = True
                return True
        return False

    def get_rules_status(self) -> List[Dict]:
        return [
            {
                "rule_id":     rid,
                "name":        meta["name"],
                "description": meta["description"],
                "type":        meta["type"],
                "query":       meta["query"],
                "threshold":   meta["threshold"],
                "window":      meta["window"],
                "severity":    RULE_SEVERITY.get(rid, "medium"),
                "tags":        meta["tags"],
                "mitre":       meta["mitre"],
                "enabled":     True,
                "fired_count": sum(1 for a in self._alerts if a.rule_id == rid),
            }
            for rid, meta in RULE_META.items()
        ]

    def get_stats(self) -> Dict:
        alerts = list(self._alerts)
        active = [a for a in alerts if not a.dismissed]
        return {
            "total_alerts":  len(alerts),
            "active_alerts": len(active),
            "critical":      sum(1 for a in active if a.severity == "critical"),
            "high":          sum(1 for a in active if a.severity == "high"),
            "medium":        sum(1 for a in active if a.severity == "medium"),
            "by_rule":       {rid: sum(1 for a in active if a.rule_id == rid) for rid in RULE_META},
        }

    def _can_fire(self, rule_key: str, now: float, cooldown: float) -> bool:
        last = self._last_alert.get(rule_key, 0)
        if now - last >= cooldown:
            self._last_alert[rule_key] = now
            return True
        return False


# Singleton
rules_engine = DetectionRulesEngine()
