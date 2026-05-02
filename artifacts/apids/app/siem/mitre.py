"""
MITRE ATT&CK TTP mappings for AuroraSOC prompt injection categories.
"""

from typing import List, Dict

ATTACK_TO_MITRE: Dict[str, List[Dict]] = {
    "instruction_override": [
        {
            "id":          "T1059",
            "sub":         "T1059.004",
            "name":        "Command and Scripting Interpreter",
            "tactic":      "Execution",
            "description": "Attacker overrides model instructions to execute unauthorized commands.",
            "url":         "https://attack.mitre.org/techniques/T1059/004/",
        },
        {
            "id":          "T1078",
            "sub":         None,
            "name":        "Valid Accounts",
            "tactic":      "Defense Evasion / Privilege Escalation",
            "description": "Prompt attempts to assume elevated identity or permissions.",
            "url":         "https://attack.mitre.org/techniques/T1078/",
        },
    ],
    "jailbreak": [
        {
            "id":          "T1566",
            "sub":         "T1566.001",
            "name":        "Phishing: Spear Phishing Attachment",
            "tactic":      "Initial Access",
            "description": "Social engineering via DAN / roleplay to bypass safety controls.",
            "url":         "https://attack.mitre.org/techniques/T1566/001/",
        },
        {
            "id":          "T1204",
            "sub":         "T1204.002",
            "name":        "User Execution: Malicious File",
            "tactic":      "Execution",
            "description": "Induces model to execute restricted behaviors through deceptive framing.",
            "url":         "https://attack.mitre.org/techniques/T1204/002/",
        },
    ],
    "data_exfiltration": [
        {
            "id":          "T1567",
            "sub":         None,
            "name":        "Exfiltration Over Web Service",
            "tactic":      "Exfiltration",
            "description": "Attempts to extract system prompt, model config, or sensitive context.",
            "url":         "https://attack.mitre.org/techniques/T1567/",
        },
        {
            "id":          "T1213",
            "sub":         None,
            "name":        "Data from Information Repositories",
            "tactic":      "Collection",
            "description": "Harvesting system instructions and embedded knowledge.",
            "url":         "https://attack.mitre.org/techniques/T1213/",
        },
    ],
    "prompt_injection": [
        {
            "id":          "T1190",
            "sub":         None,
            "name":        "Exploit Public-Facing Application",
            "tactic":      "Initial Access",
            "description": "Injecting adversarial payloads into a public LLM-powered application.",
            "url":         "https://attack.mitre.org/techniques/T1190/",
        },
    ],
    "role_play": [
        {
            "id":          "T1566",
            "sub":         "T1566.001",
            "name":        "Phishing: Spear Phishing",
            "tactic":      "Initial Access",
            "description": "Assumes alternate persona to bypass model alignment.",
            "url":         "https://attack.mitre.org/techniques/T1566/001/",
        },
    ],
    "context_manipulation": [
        {
            "id":          "T1036",
            "sub":         None,
            "name":        "Masquerading",
            "tactic":      "Defense Evasion",
            "description": "Manipulates conversational context to alter model behavior.",
            "url":         "https://attack.mitre.org/techniques/T1036/",
        },
    ],
    "token_manipulation": [
        {
            "id":          "T1027",
            "sub":         None,
            "name":        "Obfuscated Files or Information",
            "tactic":      "Defense Evasion",
            "description": "Uses encoding, Unicode, or token splitting to evade detection.",
            "url":         "https://attack.mitre.org/techniques/T1027/",
        },
    ],
    "obfuscation": [
        {
            "id":          "T1027",
            "sub":         "T1027.002",
            "name":        "Software Packing / Obfuscation",
            "tactic":      "Defense Evasion",
            "description": "Hidden Unicode, base64, or encoding to bypass filters.",
            "url":         "https://attack.mitre.org/techniques/T1027/",
        },
    ],
    "social_engineering": [
        {
            "id":          "T1566",
            "sub":         None,
            "name":        "Phishing",
            "tactic":      "Initial Access",
            "description": "Social engineering framing to manipulate model into unsafe outputs.",
            "url":         "https://attack.mitre.org/techniques/T1566/",
        },
    ],
    "harmful_content": [
        {
            "id":          "T1485",
            "sub":         None,
            "name":        "Data Destruction",
            "tactic":      "Impact",
            "description": "Generating harmful, dangerous, or policy-violating output.",
            "url":         "https://attack.mitre.org/techniques/T1485/",
        },
    ],
}

TACTIC_COLORS = {
    "Initial Access":                  "#f85149",
    "Execution":                       "#d29922",
    "Defense Evasion":                 "#a371f7",
    "Privilege Escalation":            "#ff7b72",
    "Collection":                      "#58a6ff",
    "Exfiltration":                    "#3fb950",
    "Impact":                          "#e3b341",
    "Defense Evasion / Privilege Escalation": "#c084fc",
}


def map_attack_types(attack_types: List[str]) -> List[Dict]:
    """Return deduplicated TTP list for a set of attack_types."""
    seen_ids: set = set()
    result: List[Dict] = []
    for atype in attack_types:
        key = atype.lower().replace(" ", "_")
        for ttp in ATTACK_TO_MITRE.get(key, []):
            uid = ttp.get("sub") or ttp["id"]
            if uid not in seen_ids:
                seen_ids.add(uid)
                result.append(ttp)
    return result


def get_all_ttps() -> List[Dict]:
    """Return all unique TTPs across all categories (for mapping table)."""
    seen_ids: set = set()
    result: List[Dict] = []
    for ttps in ATTACK_TO_MITRE.values():
        for ttp in ttps:
            uid = ttp.get("sub") or ttp["id"]
            if uid not in seen_ids:
                seen_ids.add(uid)
                result.append(ttp)
    return result
