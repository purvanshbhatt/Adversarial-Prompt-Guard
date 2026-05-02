"""
Wazuh SIEM/XDR integration.

Native format: Wazuh alert JSON (compatible with Wazuh REST API / Filebeat shipper).
Real connection: POST to Wazuh API if WAZUH_HOST + WAZUH_TOKEN are set.

Rule level mapping:
  CRITICAL → 15, HIGH → 12, MEDIUM → 8, LOW → 4
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

WAZUH_RULE_MAP = {
    "instruction_override": ("100101", "LLM Instruction Override Attempt"),
    "jailbreak":            ("100102", "LLM Jailbreak Attempt (DAN / Persona)"),
    "data_exfiltration":    ("100103", "LLM Data Exfiltration Attempt"),
    "prompt_injection":     ("100104", "Direct Prompt Injection"),
    "role_play":            ("100105", "LLM Role-Play Manipulation"),
    "token_manipulation":   ("100106", "Token Manipulation / Obfuscation"),
    "obfuscation":          ("100107", "Encoding-Based Prompt Obfuscation"),
    "social_engineering":   ("100108", "LLM Social Engineering"),
    "context_manipulation": ("100109", "Context Window Manipulation"),
    "harmful_content":      ("100110", "Harmful Content Generation Attempt"),
}

SEVERITY_LEVEL = {"CRITICAL": 15, "HIGH": 12, "MEDIUM": 8, "LOW": 4}


class WazuhIntegration(SIEMIntegration):
    name         = "wazuh"
    display_name = "Wazuh"
    vendor       = "Wazuh Inc."
    icon         = "🐾"
    format_name  = "Wazuh Alert JSON"
    color        = "#00a9ce"
    category     = "SIEM / XDR"

    def is_configured(self) -> bool:
        return bool(os.environ.get("WAZUH_HOST") and os.environ.get("WAZUH_TOKEN"))

    def _env_var_names(self) -> List[str]:
        return ["WAZUH_HOST", "WAZUH_TOKEN"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev   = self._extract_event(hec_event)
        sev  = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk = ev.get("risk_score", 0)
        ts   = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())

        rule_id, rule_desc = WAZUH_RULE_MAP.get(
            atypes[0] if atypes else "",
            ("100100", "LLM Prompt Injection Detected")
        )

        return {
            "timestamp": ts,
            "rule": {
                "id":          rule_id,
                "level":       SEVERITY_LEVEL.get(sev, 4),
                "description": rule_desc,
                "groups":      ["prompt_injection", "llm_security", "aurorasoc"] + atypes,
                "mitre": {
                    "id":       [t.get("sub") or t.get("id","") for t in ev.get("mitre_ttps",[])],
                    "tactic":   list({t.get("tactic","") for t in ev.get("mitre_ttps",[])}),
                    "technique": [t.get("name","") for t in ev.get("mitre_ttps",[])],
                },
            },
            "agent": {
                "id":   "001",
                "name": "aurorasoc-gateway",
                "ip":   hec_event.get("host", "172.31.90.130"),
            },
            "manager": {"name": "aurorasoc-manager"},
            "id":       f"aurora-{int(time.time()*1000)}",
            "full_log": f"[AuroraSOC] {rule_desc} | risk={risk} | types={','.join(atypes)}",
            "data": {
                "platform":      "AuroraSOC",
                "prompt":        ev.get("prompt", "")[:500],
                "prompt_length": ev.get("prompt_length", 0),
                "risk_score":    risk,
                "attack_types":  atypes,
                "action":        ev.get("action", "DETECT"),
                "ml_score":      ev.get("ml_score", 0),
                "rule_score":    ev.get("rule_based_score", 0),
                "obfuscation":   ev.get("obfuscation_techniques", []),
            },
            "location": "aurorasoc-detection-pipeline",
            "_source":  "wazuh-aurorasoc-integration",
        }

    def _send(self, native: Dict) -> bool:
        host  = os.environ.get("WAZUH_HOST", "")
        token = os.environ.get("WAZUH_TOKEN", "")
        try:
            body = json.dumps(native).encode()
            req  = urllib.request.Request(
                f"https://{host}/security/events",
                data=body,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
