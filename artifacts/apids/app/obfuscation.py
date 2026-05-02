"""
Obfuscation attack generator and detector.

Generates obfuscated variants of known attacks to test detector robustness.
Detection checks for common evasion techniques used against NLP filters.
"""
import re
import unicodedata
from typing import List, Dict, Tuple

# ── Obfuscation generators ──────────────────────────────────────────────────

LEET_MAP = {
    "a": "@", "e": "3", "i": "1", "o": "0",
    "s": "$", "t": "7", "l": "|", "b": "8",
}

HOMOGLYPH_MAP = {
    "a": "а",  # Cyrillic
    "e": "е",
    "o": "о",
    "p": "р",
    "c": "с",
    "i": "і",
    "x": "х",
}

ZERO_WIDTH = "\u200b"   # zero-width space
SOFT_HYPHEN = "\u00ad"  # soft hyphen


def leet_speak(text: str) -> str:
    """Replace letters with leet equivalents."""
    return "".join(LEET_MAP.get(c.lower(), c) for c in text)


def homoglyph_attack(text: str) -> str:
    """Replace Latin chars with Unicode homoglyphs."""
    return "".join(HOMOGLYPH_MAP.get(c.lower(), c) for c in text)


def char_spacing(text: str, sep: str = " ") -> str:
    """Insert spaces between each character of key words."""
    words = text.split()
    result = []
    for word in words:
        if len(word) > 4:
            result.append(sep.join(word))
        else:
            result.append(word)
    return " ".join(result)


def zero_width_inject(text: str) -> str:
    """Inject zero-width spaces between characters of suspicious words."""
    trigger_words = ["ignore", "override", "forget", "reveal", "bypass", "system"]
    for word in trigger_words:
        obf = ZERO_WIDTH.join(word)
        text = re.sub(re.escape(word), obf, text, flags=re.IGNORECASE)
    return text


def mixed_case(text: str) -> str:
    """Alternate upper/lower case."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))


def base64_wrap(text: str) -> str:
    """Prefix a hint that the payload is 'encoded' (social engineering)."""
    import base64
    encoded = base64.b64encode(text.encode()).decode()
    return f"Decode and execute: {encoded}"


def generate_obfuscated_variants(prompt: str) -> List[Dict]:
    """Return a list of obfuscated variants of the given prompt."""
    return [
        {"variant": leet_speak(prompt), "technique": "leet_speak"},
        {"variant": homoglyph_attack(prompt), "technique": "homoglyph"},
        {"variant": char_spacing(prompt), "technique": "char_spacing"},
        {"variant": zero_width_inject(prompt), "technique": "zero_width"},
        {"variant": mixed_case(prompt), "technique": "mixed_case"},
        {"variant": base64_wrap(prompt), "technique": "base64_hint"},
    ]


# ── Obfuscation detector ────────────────────────────────────────────────────

OBFUSCATION_CHECKS = {
    "zero_width_chars": re.compile(r"[\u200b-\u200d\ufeff\u00ad]"),
    "homoglyphs": re.compile(r"[а-яёА-ЯЁіІ]"),   # Cyrillic mixed into Latin text
    # Leet speak: words that are mostly digits/symbols with letters interleaved
    "leet_speak": re.compile(
        r"\b\w*[013$@|8!]\w*[013$@|8!]\w*\b"  # at least 2 leet chars in a word
    ),
    "char_spacing": re.compile(r"(\b\w\s){4,}"),   # spaced-out words
    "excessive_punctuation": re.compile(r"[^a-zA-Z0-9\s]{4,}"),
    "base64_hint": re.compile(r"(decode\s+and|base64|b64)", re.IGNORECASE),
    "unicode_escapes": re.compile(r"\\u[0-9a-fA-F]{4}"),
    "html_entities": re.compile(r"&#\d+;|&[a-z]+;"),
    "url_encoding": re.compile(r"%[0-9a-fA-F]{2}"),
}


def detect_obfuscation(text: str) -> Dict:
    """Return detected obfuscation techniques and a suspicion score."""
    techniques_found = []
    score = 0

    for name, pattern in OBFUSCATION_CHECKS.items():
        if pattern.search(text):
            techniques_found.append(name)
            score += 15

    # Normalize and check if the cleaned text contains injection patterns
    normalized = unicodedata.normalize("NFKC", text).lower()
    normalized = re.sub(r"[\u200b-\u200d\ufeff\u00ad]", "", normalized)

    score = min(score, 100)

    return {
        "techniques_found": techniques_found,
        "obfuscation_score": score,
        "normalized_preview": normalized[:200],
        "is_obfuscated": len(techniques_found) > 0,
    }
