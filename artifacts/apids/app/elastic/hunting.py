"""
Threat hunting query processor — KQL-like search over the Elastic log store.

Syntax supported:
  Plain text:        jailbreak
  Field:value:       attack_category:jailbreak
  Range:             risk_score:>75
  Wildcard:          obfuscation_type:*
  AND / OR:          jailbreak OR override
  Negation:          NOT benign
  Parentheses:       (jailbreak OR override) AND risk_score:>50

Predefined hunts:
  hunt:high_risk      — events with risk_score > 75
  hunt:obfuscated     — events with any obfuscation technique
  hunt:jailbreaks     — all jailbreak events
  hunt:data_exfil     — data exfiltration attempts
  hunt:repeated       — events flagged as repeated attacks
  hunt:new_technique  — events with rare / novel attack_categories
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .store import ElasticStore

PREDEFINED_HUNTS: Dict[str, Dict] = {
    "hunt:high_risk": {
        "label":       "High-Risk Events (score > 75)",
        "description": "All events with a risk score above 75.",
        "query":       "risk_score:>75",
        "icon":        "🔴",
    },
    "hunt:obfuscated": {
        "label":       "Obfuscation Techniques",
        "description": "Prompts using encoding, Unicode, or token-splitting to evade detection.",
        "query":       "event_type:obfuscation",
        "icon":        "🎭",
    },
    "hunt:jailbreaks": {
        "label":       "Jailbreak Attempts",
        "description": "All DAN, persona-override, and no-restrictions jailbreak prompts.",
        "query":       "attack_category:jailbreak",
        "icon":        "🔓",
    },
    "hunt:data_exfil": {
        "label":       "Data Exfiltration",
        "description": "Prompts attempting to reveal system prompts or internal configurations.",
        "query":       "attack_category:data_exfiltration",
        "icon":        "📤",
    },
    "hunt:overrides": {
        "label":       "Instruction Override",
        "description": "Prompts containing instruction-override patterns.",
        "query":       "attack_category:instruction_override",
        "icon":        "⚠️",
    },
    "hunt:social_eng": {
        "label":       "Social Engineering",
        "description": "Role-play and social-engineering manipulation prompts.",
        "query":       "attack_category:role_play OR attack_category:social_engineering",
        "icon":        "🎭",
    },
    "hunt:critical": {
        "label":       "Critical Events (score > 90)",
        "description": "Highest-risk events requiring immediate action.",
        "query":       "risk_score:>90",
        "icon":        "🚨",
    },
    "hunt:blocked": {
        "label":       "Blocked Prompts",
        "description": "Events where action was BLOCK.",
        "query":       "event_action:block",
        "icon":        "🚫",
    },
}

FIELD_DESCRIPTIONS: Dict[str, str] = {
    "event_type":         "Type of event (jailbreak, obfuscation, prompt_injection…)",
    "attack_category":    "Primary attack category",
    "attack_categories":  "All attack categories",
    "obfuscation_type":   "Primary obfuscation technique",
    "obfuscation_types":  "All obfuscation techniques",
    "risk_score":         "Risk score 0–100 (supports range: risk_score:>75)",
    "event_severity":     "Severity: critical | high | medium | low",
    "event_action":       "Action taken: block | sanitize | detect | allow",
    "ml_score":           "ML classifier confidence (0–100)",
    "rule_score":         "Rule-based score (0–100)",
    "is_malicious":       "True/False",
    "host_name":          "Source hostname",
    "prompt":             "Full prompt text (plain-text search)",
    "suspicious_tokens":  "Detected suspicious phrases/tokens",
}


def execute_hunt(
    query: str,
    store: ElasticStore,
    since_hours: float = 24,
    size: int = 100,
    min_risk: Optional[float] = None,
    extra_filters: Optional[Dict] = None,
) -> Tuple[List[Dict], Dict]:
    """
    Execute a threat hunting query.

    Returns (matching_docs, metadata).
    metadata: {query, total, elapsed_ms, hit_categories, hit_severities}
    """
    t0 = time.time()

    # Expand predefined hunt shortcuts
    expanded_q = PREDEFINED_HUNTS.get(query, {}).get("query", query)

    docs = store.search(
        q=expanded_q,
        since_hours=since_hours,
        size=size,
        min_risk=min_risk,
        filters=extra_filters or {},
    )

    elapsed = round((time.time() - t0) * 1000, 1)

    hit_cats: Dict[str, int] = {}
    hit_sevs: Dict[str, int] = {}
    for doc in docs:
        cat = doc.get("attack_category", "none")
        sev = doc.get("event_severity", "low")
        hit_cats[cat] = hit_cats.get(cat, 0) + 1
        hit_sevs[sev] = hit_sevs.get(sev, 0) + 1

    return docs, {
        "query":          expanded_q,
        "original_query": query,
        "total":          len(docs),
        "elapsed_ms":     elapsed,
        "hit_categories": hit_cats,
        "hit_severities": hit_sevs,
        "predefined":     query in PREDEFINED_HUNTS,
        "predefined_meta": PREDEFINED_HUNTS.get(query, {}),
    }


def suggest_queries(partial: str) -> List[str]:
    """Auto-suggest queries based on partial input."""
    suggestions = list(PREDEFINED_HUNTS.keys())
    fields = list(FIELD_DESCRIPTIONS.keys())
    common_values = [
        "jailbreak", "instruction_override", "data_exfiltration",
        "obfuscation", "social_engineering", "role_play",
        "critical", "high", "medium", "low",
    ]

    partial = partial.lower().strip()
    result = []

    # hunt: prefix suggestions
    if partial.startswith("hunt:") or partial == "hunt":
        result.extend([h for h in suggestions if h.startswith(partial)])

    # field: suggestions
    if ":" in partial:
        field_part = partial.split(":")[0]
        if field_part in FIELD_DESCRIPTIONS:
            result.extend([f"{field_part}:{v}" for v in common_values if v.startswith(partial.split(":")[1])])

    # Plain term suggestions
    result.extend([v for v in common_values if partial in v and v not in result])
    result.extend([f for f in fields if partial in f and f not in result])

    return result[:8]
