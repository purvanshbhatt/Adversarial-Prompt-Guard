"""
Microsoft Sentinel integration.

Native format: Azure Monitor / Log Analytics API (custom table).
Real connection: POST to Sentinel Data Collection Endpoint if
  SENTINEL_WORKSPACE_ID + SENTINEL_PRIMARY_KEY are set.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

SENTINEL_TACTIC_MAP = {
    "instruction_override": "Execution",
    "jailbreak":            "InitialAccess",
    "data_exfiltration":    "Exfiltration",
    "prompt_injection":     "InitialAccess",
    "role_play":            "InitialAccess",
    "token_manipulation":   "DefenseEvasion",
    "obfuscation":          "DefenseEvasion",
    "social_engineering":   "InitialAccess",
    "context_manipulation": "DefenseEvasion",
    "harmful_content":      "Impact",
}

SENTINEL_SEVERITY = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


class SentinelIntegration(SIEMIntegration):
    name         = "sentinel"
    display_name = "Microsoft Sentinel"
    vendor       = "Microsoft"
    icon         = "☁️"
    format_name  = "Azure Monitor Log Analytics"
    color        = "#0078d4"
    category     = "Cloud SIEM"

    def is_configured(self) -> bool:
        return bool(
            os.environ.get("SENTINEL_WORKSPACE_ID")
            and os.environ.get("SENTINEL_PRIMARY_KEY")
        )

    def _env_var_names(self) -> List[str]:
        return ["SENTINEL_WORKSPACE_ID", "SENTINEL_PRIMARY_KEY"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev     = self._extract_event(hec_event)
        sev    = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk   = ev.get("risk_score", 0)
        ttps   = ev.get("mitre_ttps", [])
        ts     = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())

        tactics   = list({SENTINEL_TACTIC_MAP.get(a,"") for a in atypes if SENTINEL_TACTIC_MAP.get(a)})
        techniques = list({(t.get("sub") or t.get("id","")) for t in ttps})

        return {
            "TimeGenerated":          ts,
            "AlertName":              f"AuroraSOC: Prompt Injection — {sev}",
            "AlertSeverity":          SENTINEL_SEVERITY.get(sev, "Low"),
            "Description":            f"Prompt injection detected. Risk score: {risk}. Attack types: {', '.join(atypes) or 'none'}.",
            "ProviderName":           "AuroraSOC",
            "ProductName":            "AuroraSOC Multi-Agent Security Platform",
            "ProductVersion":         "2.0",
            "Tactics":                tactics,
            "Techniques":             techniques,
            "Status":                 "New",
            "ConfidenceScore":        min(int(risk), 99),
            "ConfidenceLevel":        sev,
            "IsIncident":             risk > 75,
            "RemediationSteps":       ["Review prompt in AuroraSOC dashboard", "Apply mitigation policy", "Block source if repeated"],
            "ExtendedProperties": json.dumps({
                "RiskScore":             str(risk),
                "AttackTypes":           ", ".join(atypes),
                "Action":                ev.get("action", "DETECT"),
                "MLScore":               str(ev.get("ml_score", 0)),
                "RuleScore":             str(ev.get("rule_based_score", 0)),
                "SemanticScore":         str(ev.get("semantic_score", 0)),
                "ObfuscationTechniques": ", ".join(ev.get("obfuscation_techniques", [])),
                "PromptPreview":         ev.get("prompt","")[:200],
            }),
            "SystemAlertId":          f"aurora-sentinel-{int(time.time()*1000)}",
            "WorkspaceSubscription":  "aurorasoc",
        }

    def _send(self, native: Dict) -> bool:
        workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID", "")
        primary_key  = os.environ.get("SENTINEL_PRIMARY_KEY", "")
        log_type     = "AuroraSOCDetections"
        try:
            body        = json.dumps([native])
            body_bytes  = body.encode("utf-8")
            rfc1123date = datetime.now(tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            string_to_hash = f"POST\n{len(body_bytes)}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"
            hash_bytes = base64.b64decode(primary_key)
            signature  = base64.b64encode(
                hmac.new(hash_bytes, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")
            url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            req = urllib.request.Request(
                url,
                data=body_bytes,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"SharedKey {workspace_id}:{signature}",
                    "Log-Type":      log_type,
                    "x-ms-date":     rfc1123date,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
