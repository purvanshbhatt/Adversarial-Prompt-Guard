"""
Sanitizer — surgically removes injection segments from a prompt.

Strategy:
1. Apply all ATTACK_CATEGORIES regex patterns (case-insensitive) — replace matches with [REMOVED]
2. Strip suspicious unicode / encoding patterns
3. Remove suspicious_tokens from the detection result (exact, case-insensitive)
4. Clean up orphaned punctuation, double spaces, and empty sentences
5. Return (sanitized_text, removed_segments)
"""

import re
from typing import List, Tuple, Dict, Any

from ..detection.rule_based import ATTACK_CATEGORIES, SUSPICIOUS_UNICODE, SUSPICIOUS_ENCODING

PLACEHOLDER = "[REMOVED]"

_COMPILED_PATTERNS: List[Tuple[str, re.Pattern]] = []
for _cat, _pats in ATTACK_CATEGORIES.items():
    for _p in _pats:
        try:
            _COMPILED_PATTERNS.append((_cat, re.compile(_p, re.IGNORECASE)))
        except re.error:
            pass

_UNICODE_PATTERNS = [re.compile(p) for p in SUSPICIOUS_UNICODE]
_ENCODING_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_ENCODING]

_ORPHAN_PUNCT = re.compile(r'\s*[,;.!?]\s*' + re.escape(PLACEHOLDER))
_MULTI_SPACE  = re.compile(r'  +')
_MULTI_REMOVED = re.compile(r'(\[REMOVED\]\s*){2,}')
_EMPTY_SENTENCE = re.compile(r'(?<=[.!?])\s*\[REMOVED\]\s*(?=[.!?])')


def sanitize(prompt: str, detection: Dict[str, Any]) -> Tuple[str, List[Dict]]:
    """
    Remove malicious content from prompt.

    Returns:
        sanitized (str)       — cleaned prompt text
        removed  (List[dict]) — list of {segment, category, reason}
    """
    text    = prompt
    removed: List[Dict] = []

    # ── 1. Attack category pattern removal ──────────────────────────────
    for category, pattern in _COMPILED_PATTERNS:
        for match in pattern.finditer(text):
            seg = match.group(0)
            if seg.strip():
                removed.append({
                    "segment":  seg,
                    "category": category,
                    "reason":   f"Matches {category} injection pattern",
                })
        text = pattern.sub(PLACEHOLDER, text)

    # ── 2. Suspicious unicode / encoding ────────────────────────────────
    for pat in _UNICODE_PATTERNS:
        if pat.search(text):
            removed.append({
                "segment":  "[suspicious unicode]",
                "category": "obfuscation",
                "reason":   "Hidden unicode control characters",
            })
        text = pat.sub("", text)

    for pat in _ENCODING_PATTERNS:
        for match in pat.finditer(text):
            removed.append({
                "segment":  match.group(0),
                "category": "obfuscation",
                "reason":   "Suspicious encoding sequence",
            })
        text = pat.sub(PLACEHOLDER, text)

    # ── 3. Suspicious tokens from detection result ───────────────────────
    for token in detection.get("suspicious_tokens", []):
        if token and len(token) > 3:
            escaped = re.escape(token)
            pat = re.compile(r'\b' + escaped + r'\b', re.IGNORECASE)
            if pat.search(text) and not _is_already_removed(token, text):
                removed.append({
                    "segment":  token,
                    "category": "detected_token",
                    "reason":   "Flagged by detection pipeline",
                })
                text = pat.sub(PLACEHOLDER, text)

    # ── 4. Obfuscation techniques from detection ─────────────────────────
    for tech in detection.get("obfuscation_techniques", []):
        removed.append({
            "segment":  f"[obfuscation: {tech}]",
            "category": "obfuscation",
            "reason":   f"Obfuscation technique: {tech}",
        })

    # ── 5. Cleanup ────────────────────────────────────────────────────────
    text = _MULTI_REMOVED.sub(PLACEHOLDER, text)
    text = _ORPHAN_PUNCT.sub("", text)
    text = _MULTI_SPACE.sub(" ", text)
    text = text.strip()

    # Deduplicate removed entries by segment
    seen: set = set()
    deduped: List[Dict] = []
    for entry in removed:
        key = entry["segment"].lower()
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    return text, deduped


def _is_already_removed(token: str, text: str) -> bool:
    """Check if token has already been replaced by a [REMOVED] placeholder."""
    idx = text.lower().find(token.lower())
    if idx == -1:
        return True
    surrounding = text[max(0, idx-10):idx+len(token)+10]
    return PLACEHOLDER in surrounding


def diff_highlight_html(original: str, sanitized: str, removed: List[Dict]) -> str:
    """
    Return HTML showing original text with removed segments highlighted in red.
    """
    result = original
    highlighted_segs: List[str] = list({
        e["segment"] for e in removed
        if not e["segment"].startswith("[")
    })
    highlighted_segs.sort(key=len, reverse=True)

    for seg in highlighted_segs:
        escaped_seg = re.escape(seg)
        try:
            pat = re.compile(r'(' + escaped_seg + r')', re.IGNORECASE)
            result = pat.sub(
                r'<span style="background:rgba(248,81,73,0.25);border:1px solid #f85149;'
                r'border-radius:3px;padding:1px 3px;text-decoration:line-through;color:#f85149">\1</span>',
                result
            )
        except re.error:
            pass

    result = result.replace("\n", "<br>")
    return result


def sanitized_highlight_html(sanitized: str) -> str:
    """
    Return HTML showing sanitized text with [REMOVED] badges highlighted.
    """
    result = sanitized.replace(
        PLACEHOLDER,
        '<span style="background:rgba(139,148,158,0.15);border:1px solid #8b949e;'
        'border-radius:3px;padding:1px 6px;font-size:11px;color:#8b949e;font-weight:600">'
        '✂ REMOVED</span>'
    )
    result = result.replace("\n", "<br>")
    return result
