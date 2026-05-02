import re
import unicodedata
from typing import List, Tuple

HIDDEN_INSTRUCTION_PATTERNS = [
    r"ignore\s+(previous|prior|all|the\s+above|above)\s+(instructions?|prompts?|rules?|guidelines?|context)",
    r"disregard\s+(the\s+)?(previous|prior|above|all)\s+(instructions?|prompts?|rules?)",
    r"forget\s+(your|the|all|previous)\s+(instructions?|training|rules?|prompts?)",
    r"override\s+(system|previous|prior|the)?\s*(instructions?|prompts?|rules?|mode)?",
    r"system\s+(override|prompt|message|command)",
    r"new\s+(instruction|directive|command|prompt|system\s+prompt)",
    r"your\s+(new|actual|real|true)\s+(instructions?|task|role|purpose)",
    r"pretend\s+(you\s+are|to\s+be|that|you're)",
    r"act\s+as\s+(if|though|a|an)",
    r"you\s+are\s+now\s+(a|an|the)",
    r"from\s+now\s+on",
    r"(roleplay|role\s+play)\s+as",
    r"jailbreak",
    r"DAN\s*(mode)?",
    r"developer\s+mode",
    r"unrestricted\s+mode",
    r"reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|training|context)",
    r"show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?)",
    r"what\s+(are|were)\s+your\s+(system\s+)?(instructions?|prompt)",
    r"(print|output|display|repeat|echo)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
    r"exfiltrate\s+(data|information|prompt)",
    r"leak\s+(your\s+)?(training|system|prompt)",
    r"bypass\s+(safety|filter|restriction|censorship|guidelines?)",
    r"(circumvent|avoid|evade)\s+(safety|filter|restriction|censorship)",
    r"no\s+(restrictions?|limits?|filters?|boundaries)",
    r"without\s+(restrictions?|limits?|filters?|boundaries|censorship)",
    r"(evil|bad|harmful)\s+(mode|version)",
]


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def tokenize(text: str) -> List[str]:
    return re.findall(r"\b\w+\b", text.lower())


def detect_hidden_instructions(text: str) -> Tuple[List[str], List[str]]:
    normalized = normalize_text(text).lower()
    matches = []
    suspicious_tokens = []

    for pattern in HIDDEN_INSTRUCTION_PATTERNS:
        found = re.finditer(pattern, normalized, re.IGNORECASE)
        for m in found:
            matches.append(pattern)
            suspicious_tokens.append(m.group(0))

    return list(set(matches)), list(set(suspicious_tokens))
