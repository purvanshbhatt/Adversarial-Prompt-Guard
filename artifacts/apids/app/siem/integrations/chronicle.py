"""
Google Chronicle (Google SecOps) integration.

Native format: Chronicle UDM (Unified Data Model) event.
Real connection: POST to Chronicle Ingestion API if
  CHRONICLE_CUSTOMER_ID + CHRONICLE_SERVICE_ACCOUNT_JSON are set.
"""

import base64
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

CHRONICLE_EVENT_TYPE = {
    "instruction_override": "NETWORK_CONNECTION",
    "jailbreak":            "USER_LOGIN",
    "data_exfiltration":    "FILE_READ",
    "prompt_injection":     "NETWORK_HTTP",
    "role_play":            "USER_CHANGE_PERMISSIONS",
    "token_manipulation":   "PROCESS_LAUNCH",
    "obfuscation":          "PROCESS_LAUNCH",
    "social_engineering":   "EMAIL_TRANSACTION",
    "context_manipulation": "NETWORK_CONNECTION",
    "harmful_content":      "FILE_MODIFICATION",
}


class ChronicleIntegration(SIEMIntegration):
    name         = "chronicle"
    display_name = "Google Chronicle"
    vendor       = "Google"
    icon         = "🌐"
    format_name  = "Chronicle UDM"
    color        = "#4285f4"
    category     = "Cloud SIEM"

    def is_configured(self) -> bool:
        return bool(os.environ.get("CHRONICLE_CUSTOMER_ID"))

    def _env_var_names(self) -> List[str]:
        return ["CHRONICLE_CUSTOMER_ID", "CHRONICLE_SERVICE_ACCOUNT_JSON"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev      = self._extract_event(hec_event)
        sev     = ev.get("severity", "LOW")
        atypes  = ev.get("attack_types", [])
        risk    = ev.get("risk_score", 0)
        ttps    = ev.get("mitre_ttps", [])
        ts      = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())
        ev_type = CHRONICLE_EVENT_TYPE.get(atypes[0] if atypes else "", "GENERIC_EVENT")

        return {
            "events": [{
                "metadata": {
                    "eventTimestamp":    ts,
                    "eventType":         ev_type,
                    "productName":       "AuroraSOC",
                    "vendorName":        "AuroraSOC",
                    "productEventType":  "PROMPT_INJECTION",
                    "collectedTimestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "id": {
                        "customerIdString": os.environ.get("CHRONICLE_CUSTOMER_ID","aurora"),
                        "collectionIdString": f"aurora-{int(time.time()*1000)}",
                    },
                    "ingestedTimestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "enrichmentState": "ENRICHED",
                },
                "principal": {
                    "hostname":    hec_event.get("host","aurorasoc-01"),
                    "ip":          ["172.31.90.130"],
                    "application": "aurorasoc-detection-engine",
                    "user": {"userid": "llm-gateway"},
                },
                "target": {
                    "application": "llm-model-endpoint",
                    "url":         "internal://llm-gateway",
                },
                "securityResult": [{
                    "action":        ["BLOCK" if ev.get("action")=="BLOCK" else "ALLOW"],
                    "severity":      sev,
                    "severityDetails": f"Risk score: {risk}",
                    "summary":       f"Prompt injection — {', '.join(atypes) or 'unknown'}",
                    "ruleName":      "AuroraSOC Prompt Injection Detector",
                    "ruleVersion":   "2.0",
                    "description":   ev.get("explanation","")[:300],
                    "category":      "NETWORK_SUSPICIOUS",
                    "attackDetails": {
                        "techniques": [
                            {"id": t.get("sub") or t.get("id",""), "name": t.get("name","")}
                            for t in ttps
                        ],
                        "tactics": [
                            {"name": t.get("tactic","")} for t in ttps
                        ],
                    },
                }],
                "extensions": {
                    "aurora": {
                        "riskScore":       risk,
                        "attackTypes":     atypes,
                        "mlScore":         ev.get("ml_score",0),
                        "ruleScore":       ev.get("rule_based_score",0),
                        "promptLength":    ev.get("prompt_length",0),
                        "obfuscation":     ev.get("obfuscation_techniques",[]),
                    }
                },
            }]
        }

    def _send(self, native: Dict) -> bool:
        customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID","")
        sa_json     = os.environ.get("CHRONICLE_SERVICE_ACCOUNT_JSON","")
        try:
            # In production: use google-auth to get token from sa_json
            body = json.dumps(native).encode()
            req  = urllib.request.Request(
                f"https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate?customerId={customer_id}",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
