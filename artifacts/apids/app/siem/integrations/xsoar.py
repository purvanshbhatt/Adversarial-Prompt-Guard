"""
Palo Alto XSOAR (Cortex XSOAR) integration.

Native format: XSOAR Incident creation payload.
Real connection: POST to XSOAR REST API if
  XSOAR_HOST + XSOAR_API_KEY are set.
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

XSOAR_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
XSOAR_SEVERITY_NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}


class XSOARIntegration(SIEMIntegration):
    name         = "xsoar"
    display_name = "Palo Alto XSOAR"
    vendor       = "Palo Alto Networks"
    icon         = "🔥"
    format_name  = "XSOAR Incident"
    color        = "#fa582d"
    category     = "SOAR"

    def is_configured(self) -> bool:
        return bool(os.environ.get("XSOAR_HOST") and os.environ.get("XSOAR_API_KEY"))

    def _env_var_names(self) -> List[str]:
        return ["XSOAR_HOST", "XSOAR_API_KEY"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev     = self._extract_event(hec_event)
        sev    = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk   = ev.get("risk_score", 0)
        ttps   = ev.get("mitre_ttps", [])
        ts     = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())
        sev_num = XSOAR_SEVERITY.get(sev, 1)

        playbook_map = {
            "jailbreak":            "Prompt Injection Response",
            "data_exfiltration":    "Data Exfiltration Response",
            "instruction_override": "Instruction Override Response",
        }
        playbook = next(
            (playbook_map[a] for a in atypes if a in playbook_map),
            "Generic Prompt Injection Response"
        )

        return {
            "name":           f"Prompt Injection Detected — {sev} ({', '.join(atypes) or 'unknown'})",
            "type":           "Prompt Injection",
            "severity":       sev_num,
            "occurred":       ts,
            "details":        f"Risk score: {risk}. Attack types: {', '.join(atypes)}. Action: {ev.get('action','DETECT')}.",
            "owner":          "AuroraSOC",
            "playbookId":     playbook,
            "labels": [
                {"type": "platform",     "value": "AuroraSOC"},
                {"type": "risk_score",   "value": str(risk)},
                {"type": "action",       "value": ev.get("action","DETECT")},
            ] + [{"type": "attack_type", "value": a} for a in atypes]
              + [{"type": "mitre_ttp",   "value": t.get("sub") or t.get("id","")} for t in ttps],
            "CustomFields": {
                "aurorasocriskScore":        risk,
                "aurorasocattackTypes":      ", ".join(atypes),
                "aurorasocaction":           ev.get("action","DETECT"),
                "aurorasocmlScore":          ev.get("ml_score",0),
                "aurorasocruleScore":        ev.get("rule_based_score",0),
                "aurorasocsemanticScore":    ev.get("semantic_score",0),
                "aurorasocpromptPreview":    ev.get("prompt","")[:300],
                "aurorasocmitreTechniques":  ", ".join(t.get("sub") or t.get("id","") for t in ttps),
                "aurorasocmitreTactics":     ", ".join({t.get("tactic","") for t in ttps}),
            },
            "rawJSON": json.dumps({
                "source":     "AuroraSOC",
                "event":      ev,
                "hec_meta": {
                    "host":       hec_event.get("host",""),
                    "sourcetype": hec_event.get("sourcetype",""),
                    "index":      hec_event.get("index",""),
                },
            }),
        }

    def _send(self, native: Dict) -> bool:
        host    = os.environ.get("XSOAR_HOST", "")
        api_key = os.environ.get("XSOAR_API_KEY", "")
        try:
            body = json.dumps(native).encode()
            req  = urllib.request.Request(
                f"https://{host}/incident",
                data=body,
                headers={
                    "Content-Type":    "application/json",
                    "Authorization":   api_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
