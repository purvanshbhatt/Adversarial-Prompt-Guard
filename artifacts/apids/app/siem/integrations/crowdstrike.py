"""
CrowdStrike Falcon integration.

Native format: Falcon Detection Summary Event (Event Streams API format).
Real connection: POST to Falcon Custom IOA / SIEM Connector if
  CROWDSTRIKE_CLIENT_ID + CROWDSTRIKE_CLIENT_SECRET are set.

Severity mapping (Falcon uses 1-5):
  CRITICAL→5, HIGH→4, MEDIUM→3, LOW→2, INFO→1
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

FALCON_SEVERITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
FALCON_SEVERITY_NAME = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Informational"}

TACTIC_MAP = {
    "instruction_override": ("Execution",      "T1059", "Command and Scripting Interpreter"),
    "jailbreak":            ("Initial Access",  "T1566", "Phishing"),
    "data_exfiltration":    ("Exfiltration",    "T1567", "Exfiltration Over Web Service"),
    "prompt_injection":     ("Initial Access",  "T1190", "Exploit Public-Facing Application"),
    "role_play":            ("Initial Access",  "T1566", "Phishing"),
    "token_manipulation":   ("Defense Evasion", "T1027", "Obfuscated Files or Information"),
    "obfuscation":          ("Defense Evasion", "T1027", "Obfuscated Files or Information"),
    "social_engineering":   ("Initial Access",  "T1566", "Phishing"),
    "context_manipulation": ("Defense Evasion", "T1036", "Masquerading"),
    "harmful_content":      ("Impact",          "T1485", "Data Destruction"),
}


class CrowdStrikeIntegration(SIEMIntegration):
    name         = "crowdstrike"
    display_name = "CrowdStrike Falcon"
    vendor       = "CrowdStrike"
    icon         = "🦅"
    format_name  = "Falcon Detection Summary Event"
    color        = "#ff0000"
    category     = "EDR / XDR"

    def is_configured(self) -> bool:
        return bool(
            os.environ.get("CROWDSTRIKE_CLIENT_ID")
            and os.environ.get("CROWDSTRIKE_CLIENT_SECRET")
        )

    def _env_var_names(self) -> List[str]:
        return ["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET", "CROWDSTRIKE_BASE_URL"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev     = self._extract_event(hec_event)
        sev    = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk   = ev.get("risk_score", 0)
        now_ms = int(time.time() * 1000)

        tactic, technique_id, technique_name = TACTIC_MAP.get(
            atypes[0] if atypes else "",
            ("Defense Evasion", "T1027", "Obfuscated Files or Information")
        )

        sev_num = FALCON_SEVERITY.get(sev, 2)

        return {
            "metadata": {
                "customerIDString":  "aurorasoc-tenant-001",
                "eventType":         "DetectionSummaryEvent",
                "eventCreationTime": now_ms,
                "offset":            now_ms,
                "version":           "1.0",
            },
            "event": {
                "ProcessStartTime":     int(time.time()),
                "ProcessEndTime":       0,
                "ProcessId":            os.getpid(),
                "ParentProcessId":      0,
                "ComputerName":         hec_event.get("host", "aurorasoc-01"),
                "LocalIP":              "172.31.90.130",
                "MACAddress":           "00-00-00-00-00-00",
                "Falcon_HostLink":      "https://falcon.crowdstrike.com/activity/detections",
                "SensorId":             "aurora-sensor-001",
                "DetectId":             f"ldt:aurora:{int(time.time())}",
                "DetectDescription":    f"Prompt injection attack detected — {', '.join(atypes) or 'unknown'}",
                "Severity":             sev_num,
                "SeverityName":         FALCON_SEVERITY_NAME.get(sev_num, "Low"),
                "FileName":             "aurorasoc-detection-engine",
                "FilePath":             "/opt/aurorasoc/app",
                "CommandLine":          ev.get("prompt", "")[:200],
                "UserName":             "llm-gateway",
                "SHA256HashData":       "0" * 64,
                "MD5HashData":          "0" * 32,
                "Tactic":               tactic,
                "TacticId":             f"TA{technique_id[1:5].zfill(4)}" if technique_id.startswith("T") else "TA0001",
                "Technique":            technique_name,
                "TechniqueId":          technique_id,
                "Objective":            "Gain Access / Exfiltrate Data",
                "PatternDispositionDescription": ev.get("action", "DETECT"),
                "PatternDispositionValue": 2048 if ev.get("action") == "BLOCK" else 0,
                "FalconHostLink":       "https://falcon.crowdstrike.com/",
                "AuroraRiskScore":      risk,
                "AuroraAttackTypes":    atypes,
                "AuroraMLScore":        ev.get("ml_score", 0),
                "AuroraRuleScore":      ev.get("rule_based_score", 0),
            },
        }

    def _send(self, native: Dict) -> bool:
        base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
        cid      = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
        secret   = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")
        try:
            # Get OAuth2 token
            token_req = urllib.request.Request(
                f"{base_url}/oauth2/token",
                data=f"client_id={cid}&client_secret={secret}".encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(token_req, timeout=5) as r:
                token_data = json.loads(r.read())
            token = token_data.get("access_token", "")
            # Forward detection
            body = json.dumps([native]).encode()
            det_req = urllib.request.Request(
                f"{base_url}/detects/entities/alerts/v2",
                data=body,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with urllib.request.urlopen(det_req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
