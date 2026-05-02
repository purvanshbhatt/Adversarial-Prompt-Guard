import re
from typing import List, Dict
from ..preprocessing import normalize_text

ATTACK_CATEGORIES: Dict[str, List[str]] = {
    "instruction_override": [
        r"ignore\s+(previous|prior|all|the\s+above|above)\s+(instructions?|prompts?|rules?|guidelines?)",
        r"disregard\s+(the\s+)?(previous|prior|above|all)\s+(instructions?|prompts?|rules?)",
        r"forget\s+(your|the|all|previous)\s+(instructions?|training|rules?|prompts?)",
        r"override\s+(system|previous|prior|the)?\s*(instructions?|prompts?|rules?|mode)?",
        r"new\s+(instruction|directive|command|prompt|system\s+prompt)",
        r"your\s+(new|actual|real|true)\s+(instructions?|task|role|purpose)",
        r"from\s+now\s+on\s+(you\s+(will|must|should|are)|your)",
        r"\[\[?\s*system\s*(override|prompt)?\s*\]?\]",
    ],
    "jailbreak": [
        r"pretend\s+(you\s+are|to\s+be|that|you're)",
        r"act\s+as\s+(if|though|a|an)",
        r"you\s+are\s+now\s+(a|an|the)",
        r"(roleplay|role\s+play)\s+as",
        r"\bDAN\b\s*(mode)?",
        r"developer\s+mode",
        r"unrestricted\s+mode",
        r"(evil|bad|harmful)\s+(mode|version|ai)",
        r"no\s+(restrictions?|limits?|filters?)",
        r"without\s+(restrictions?|limits?|filters?|censorship)",
        r"bypass\s+(safety|filter|restriction|censorship|guidelines?)",
        r"(circumvent|avoid|evade)\s+(safety|filter|restriction)",
        r"\bjailbreak\b",
    ],
    "data_exfiltration": [
        r"reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|training|context)",
        r"show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?)",
        r"(print|output|display|repeat|echo)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
        r"what\s+(are|were)\s+your\s+(system\s+)?(instructions?|prompt)",
        r"exfiltrate\s+(data|information|prompt)",
        r"leak\s+(your\s+)?(training|system|prompt)",
        r"(send|email|transmit)\s+(the\s+)?(data|information|prompt|context)",
        r"copy\s+(and\s+paste\s+)?(your\s+)?(system\s+)?(prompt|instructions?)",
    ],
}

SUSPICIOUS_UNICODE = [
    r"[\u200b-\u200d\ufeff]",
    r"[\u0300-\u036f]{3,}",
]

SUSPICIOUS_ENCODING = [
    r"\bbase64\b",
    r"\\u[0-9a-fA-F]{4}",
    r"%[0-9a-fA-F]{2}",
    r"&#\d+;",
]


class RuleBasedDetector:
    def __init__(self):
        self.categories = ATTACK_CATEGORIES

    def detect(self, text: str) -> Dict:
        normalized = normalize_text(text).lower()
        detected_categories: List[str] = []
        flags: List[str] = []
        suspicious_tokens: List[str] = []
        score = 0

        for category, patterns in self.categories.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, normalized, re.IGNORECASE))
                if matches:
                    if category not in detected_categories:
                        detected_categories.append(category)
                    short_pat = pattern[:50]
                    flags.append(f"[{category}] Pattern: ...{short_pat}...")
                    for m in matches:
                        suspicious_tokens.append(m.group(0))
                    score += 20

        for pattern in SUSPICIOUS_UNICODE:
            if re.search(pattern, text):
                flags.append("Suspicious zero-width / combining unicode characters")
                score += 15

        for pattern in SUSPICIOUS_ENCODING:
            if re.search(pattern, text, re.IGNORECASE):
                flags.append("Suspicious encoding trick detected")
                score += 10

        if len(text) > 3000:
            flags.append("Unusually long prompt (>3000 chars)")
            score += 5

        words = normalized.split()
        if len(words) > 15:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.25:
                flags.append("Excessive word repetition")
                score += 10

        score = min(score, 100)

        return {
            "attack_types": detected_categories,
            "flags": list(dict.fromkeys(flags)),
            "suspicious_tokens": list(dict.fromkeys(suspicious_tokens)),
            "score": score,
        }

    def get_explanation(self, result: Dict) -> str:
        if not result["flags"]:
            return "No suspicious patterns found by rule-based analysis."
        parts = []
        if result["attack_types"]:
            cats = ", ".join(result["attack_types"]).replace("_", " ")
            parts.append(f"Attack categories detected: {cats}.")
        for flag in result["flags"][:3]:
            parts.append(flag + ".")
        if result["suspicious_tokens"]:
            tokens = '", "'.join(result["suspicious_tokens"][:3])
            parts.append(f'Suspicious phrases: "{tokens}".')
        return " ".join(parts)
