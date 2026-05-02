"""
IBM QRadar SIEM integration.

Native format: LEEF 2.0 (Log Event Extended Format) + JSON sidecar.
Real connection: POST to QRadar Syslog / REST API if
  QRADAR_HOST + QRADAR_TOKEN are set.
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

LEEF_SEVERITY = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}

QRADAR_CATEGORY_MAP = {
    "instruction_override": 18000,
    "jailbreak":            18001,
    "data_exfiltration":    18002,
    "prompt_injection":     18003,
    "role_play":            18004,
    "token_manipulation":   18005,
    "obfuscation":          18006,
    "social_engineering":   18007,
    "context_manipulation": 18008,
    "harmful_content":      18009,
}


class QRadarIntegration(SIEMIntegration):
    name         = "qradar"
    display_name = "IBM QRadar"
    vendor       = "IBM"
    icon         = "🔷"
    format_name  = "LEEF 2.0"
    color        = "#1f70c1"
    category     = "Enterprise SIEM"

    def is_configured(self) -> bool:
        return bool(os.environ.get("QRADAR_HOST") and os.environ.get("QRADAR_TOKEN"))

    def _env_var_names(self) -> List[str]:
        return ["QRADAR_HOST", "QRADAR_TOKEN"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev     = self._extract_event(hec_event)
        sev    = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk   = ev.get("risk_score", 0)
        ts     = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())
        cat_id = QRADAR_CATEGORY_MAP.get(atypes[0] if atypes else "", 18000)
        sev_num = LEEF_SEVERITY.get(sev, 2)

        # LEEF 2.0 format (tab-delimited key=value pairs)
        leef_header = f"LEEF:2.0|AuroraSOC|PromptInspector|2.0|{cat_id}|\\t"
        leef_attrs  = "\t".join([
            f"devTime={ts}",
            f"devTimeFormat=ISO8601",
            f"sev={sev_num}",
            f"cat=PromptInjection",
            f"proto=HTTP",
            f"src=172.31.90.130",
            f"dst=llm-model-endpoint",
            f"usrName=llm-gateway",
            f"identSrc=AuroraSOC",
            f"attackType={','.join(atypes) or 'none'}",
            f"riskScore={risk}",
            f"action={ev.get('action','DETECT')}",
            f"mlScore={ev.get('ml_score',0)}",
            f"ruleScore={ev.get('rule_based_score',0)}",
            f"mitreTechniques={','.join(t.get('sub') or t.get('id','') for t in ev.get('mitre_ttps',[]))}",
        ])
        leef_string = f"{leef_header}{leef_attrs}"

        # JSON sidecar for structured storage
        return {
            "leef":      leef_string,
            "qradar": {
                "logSourceType":   "AuroraSOC Prompt Injection Monitor",
                "eventCategory":   cat_id,
                "eventName":       "LLM Prompt Injection Detected",
                "magnitude":       sev_num,
                "credibility":     8,
                "relevance":       9,
                "severity":        sev_num,
                "offenseType":     "AuroraSOC:PromptInjection",
                "startTime":       int(time.time() * 1000),
                "deviceTime":      int(time.time() * 1000),
                "sourceIP":        "172.31.90.130",
                "destinationIP":   "0.0.0.0",
                "username":        "llm-gateway",
                "riskScore":       risk,
                "attackTypes":     atypes,
                "mitreTechniques": [t.get("sub") or t.get("id","") for t in ev.get("mitre_ttps",[])],
                "prompt":          ev.get("prompt","")[:300],
            },
        }

    def _send(self, native: Dict) -> bool:
        host  = os.environ.get("QRADAR_HOST", "")
        token = os.environ.get("QRADAR_TOKEN", "")
        try:
            # QRadar REST API: POST custom log source event
            body = json.dumps({"events": [native["qradar"]]}).encode()
            req  = urllib.request.Request(
                f"https://{host}/api/siem/offenses",
                data=body,
                headers={
                    "Content-Type":  "application/json",
                    "SEC":           token,
                    "Accept":        "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
