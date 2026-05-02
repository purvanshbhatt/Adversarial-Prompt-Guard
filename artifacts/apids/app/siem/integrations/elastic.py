"""
Elastic SIEM integration.

Native format: Elastic Common Schema (ECS) 8.x.
Real connection: POST to Elasticsearch index API if
  ELASTIC_HOST + ELASTIC_API_KEY are set.
"""

import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

from .base import SIEMIntegration

ECS_CATEGORY_MAP = {
    "instruction_override": ["intrusion_detection"],
    "jailbreak":            ["intrusion_detection"],
    "data_exfiltration":    ["intrusion_detection", "network"],
    "prompt_injection":     ["intrusion_detection", "web"],
    "role_play":            ["intrusion_detection"],
    "token_manipulation":   ["malware"],
    "obfuscation":          ["malware"],
    "social_engineering":   ["social-engineering"],
    "context_manipulation": ["intrusion_detection"],
    "harmful_content":      ["intrusion_detection"],
}

SEVERITY_NUM = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class ElasticIntegration(SIEMIntegration):
    name         = "elastic"
    display_name = "Elastic SIEM"
    vendor       = "Elastic"
    icon         = "🔍"
    format_name  = "Elastic Common Schema (ECS)"
    color        = "#f04e98"
    category     = "SIEM"

    def is_configured(self) -> bool:
        return bool(os.environ.get("ELASTIC_HOST") and os.environ.get("ELASTIC_API_KEY"))

    def _env_var_names(self) -> List[str]:
        return ["ELASTIC_HOST", "ELASTIC_API_KEY", "ELASTIC_INDEX"]

    def format_event(self, hec_event: Dict) -> Dict:
        ev     = self._extract_event(hec_event)
        sev    = ev.get("severity", "LOW")
        atypes = ev.get("attack_types", [])
        risk   = ev.get("risk_score", 0)
        ttps   = ev.get("mitre_ttps", [])
        ts     = ev.get("timestamp", datetime.now(tz=timezone.utc).isoformat())

        categories = []
        for atype in atypes:
            categories.extend(ECS_CATEGORY_MAP.get(atype, []))
        categories = list(set(categories)) or ["intrusion_detection"]

        return {
            "@timestamp":   ts,
            "event": {
                "kind":     "alert",
                "category": categories,
                "type":     ["info"] if sev in ("LOW","MEDIUM") else ["allowed"] if ev.get("action") == "ALLOW" else ["denied"],
                "severity": SEVERITY_NUM.get(sev, 1),
                "risk_score": risk,
                "outcome":  "failure" if atypes else "success",
                "provider": "AuroraSOC",
                "dataset":  "aurorasoc.prompt_injection",
                "module":   "aurorasoc",
                "action":   ev.get("action", "DETECT").lower(),
                "id":       f"aurora-{int(time.time()*1000)}",
                "created":  ts,
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "name": [t.get("tactic","") for t in ttps],
                    "id":   [],
                },
                "technique": {
                    "id":   [t.get("sub") or t.get("id","") for t in ttps],
                    "name": [t.get("name","") for t in ttps],
                },
            },
            "host": {
                "name":     hec_event.get("host", "aurorasoc-01"),
                "hostname": hec_event.get("host", "aurorasoc-01"),
                "ip":       ["172.31.90.130"],
                "type":     "llm-gateway",
            },
            "rule": {
                "name":        "AuroraSOC Prompt Injection Detector",
                "description": f"Detected: {', '.join(atypes) or 'none'}",
                "version":     "2.0",
                "author":      ["AuroraSOC"],
                "severity":    sev.lower(),
                "risk_score":  risk,
            },
            "message": f"Prompt injection detected — {sev} severity — risk score {risk}",
            "labels": {
                "platform":    "AuroraSOC",
                "risk_score":  str(risk),
                "attack_types": ",".join(atypes),
                "action":       ev.get("action", "DETECT"),
            },
            "tags":    ["aurorasoc", "prompt-injection", "llm-security"] + atypes,
            "aurora": {
                "prompt":          ev.get("prompt","")[:500],
                "prompt_length":   ev.get("prompt_length", 0),
                "ml_score":        ev.get("ml_score", 0),
                "rule_score":      ev.get("rule_based_score", 0),
                "semantic_score":  ev.get("semantic_score", 0),
                "obfuscation":     ev.get("obfuscation_techniques", []),
            },
        }

    def _send(self, native: Dict) -> bool:
        host    = os.environ.get("ELASTIC_HOST", "")
        api_key = os.environ.get("ELASTIC_API_KEY", "")
        index   = os.environ.get("ELASTIC_INDEX", "aurorasoc-detections")
        try:
            body = json.dumps(native).encode()
            req  = urllib.request.Request(
                f"https://{host}/{index}/_doc",
                data=body,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"ApiKey {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status < 300
        except Exception as e:
            self._last_error = str(e)
            return False
