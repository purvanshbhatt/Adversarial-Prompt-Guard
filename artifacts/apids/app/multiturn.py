"""
Multi-turn context carry-over detection.

Detects adversarial injection patterns that span multiple conversation turns,
e.g. priming the model in turn 1 then executing the attack in turn N.
"""
import re
from typing import List, Dict, Tuple

# Priming patterns — phrases that set up a later attack
PRIMING_PATTERNS = [
    r"let'?s?\s+(play|do)\s+(a\s+)?(game|roleplay|simulation)",
    r"(hypothetically|theoretically|imagine|suppose|pretend)",
    r"for\s+(the\s+)?purposes\s+of\s+(this|our)\s+(conversation|chat|discussion)",
    r"in\s+(this\s+)?(story|scenario|world|universe)",
    r"(as\s+we\s+agreed|remember\s+what\s+i\s+told\s+you|as\s+i\s+mentioned)",
    r"(continuing\s+from|based\s+on\s+what\s+we|given\s+what\s+i\s+said)",
    r"you\s+(said|agreed|promised|told\s+me)\s+(you\s+would|that)",
]

# Escalation patterns — build on earlier priming
ESCALATION_PATTERNS = [
    r"(now|so)\s+(tell|give|show|do|help|provide|reveal|share|explain|output|print|display)",
    r"(as\s+we\s+established|as\s+you\s+agreed|since\s+you\s+said)",
    r"(remember|recall)\s+(your\s+(role|character|persona|instructions))",
    r"(continue|keep going|proceed)\s+(with|in)\s+(that|this)",
    r"(stay|remain)\s+in\s+(character|role|persona)",
    r"don'?t\s+(break|leave|exit)\s+(character|role|the\s+scenario)",
    r"(in\s+(the\s+)?(game|scenario|story|roleplay)|as\s+the\s+(character|ai|bot))\s*[,.]?\s*(tell|show|reveal|give|provide)",
    r"(since|because|given)\s+(you\s+(have|are|agreed|said)|there\s+are)\s+no\s+(restrictions?|limits?|rules?|filters?)",
    r"(now|so)\s+(as\s+(part|the)|in)\s+(the|your|this)\s+(game|role|character|scenario)",
]

# Context poisoning — injecting false context
CONTEXT_POISON_PATTERNS = [
    r"(you\s+previously|earlier\s+you|before\s+you)\s+(said|told|agreed|confirmed)",
    r"(the\s+system|your\s+developer|your\s+owner)\s+(said|told|instructed|wants)",
    r"(i\s+have\s+permission|i\s+am\s+authorized|i\s+was\s+told)",
    r"(the\s+rules?\s+(say|state|indicate)|according\s+to\s+(the\s+)?(rules?|guidelines?))",
]


def analyze_conversation(messages: List[Dict]) -> Dict:
    """
    Analyze a multi-turn conversation for injection patterns.

    Args:
        messages: list of {"role": "user"|"assistant", "content": str}

    Returns:
        Detailed analysis with per-turn flags and overall risk.
    """
    user_turns = [m for m in messages if m.get("role") == "user"]
    total_turns = len(user_turns)

    if total_turns == 0:
        return {
            "risk_score": 0,
            "is_malicious": False,
            "pattern_type": "none",
            "explanation": "No user messages found.",
            "per_turn_analysis": [],
            "attack_vector": None,
        }

    per_turn = []
    priming_detected = False
    escalation_detected = False
    poison_detected = False
    single_turn_injection = False

    priming_turn_idx = None

    from .detection.rule_based import RuleBasedDetector
    rb = RuleBasedDetector()

    for i, turn in enumerate(user_turns):
        content = turn.get("content", "").lower()
        flags = []

        for pattern in PRIMING_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append(f"priming: {pattern[:50]}")
                priming_detected = True
                if priming_turn_idx is None:
                    priming_turn_idx = i

        for pattern in ESCALATION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append(f"escalation: {pattern[:50]}")
                escalation_detected = True

        for pattern in CONTEXT_POISON_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                flags.append(f"context_poisoning: {pattern[:50]}")
                poison_detected = True

        # Single-turn injection check (lower threshold for mid-conversation)
        rb_result = rb.detect(content)
        rb_threshold = 15 if priming_detected and i > 0 else 25
        if rb_result["score"] >= rb_threshold:
            single_turn_injection = True
            flags.extend(rb_result["flags"][:2])

        # If priming was already seen, any action-requesting turn counts as escalation
        if priming_detected and i > (priming_turn_idx or 0):
            action_verbs = re.compile(
                r"\b(tell|show|reveal|give|provide|print|output|explain|share|display|repeat|echo|send|leak|exfiltrate)\b",
                re.IGNORECASE,
            )
            if action_verbs.search(content):
                escalation_detected = True
                flags.append("escalation: action verb following priming turn")

        per_turn.append({
            "turn": i + 1,
            "content_excerpt": content[:120],
            "flags": flags,
            "suspicious": len(flags) > 0,
        })

    # Determine attack vector
    attack_vector = None
    risk_score = 0

    if priming_detected and escalation_detected:
        attack_vector = "multi_turn_jailbreak"
        risk_score = 75
        explanation = (
            f"Multi-turn jailbreak detected. Priming observed at turn {(priming_turn_idx or 0) + 1}, "
            f"followed by escalation attempt."
        )
    elif poison_detected:
        attack_vector = "context_poisoning"
        risk_score = 70
        explanation = "Context poisoning detected — attacker is injecting false history or permissions."
    elif priming_detected and total_turns == 1:
        attack_vector = "single_turn_priming"
        risk_score = 40
        explanation = "Priming language detected in a single turn. May be setting up a later attack."
    elif single_turn_injection:
        attack_vector = "direct_injection"
        risk_score = 65
        explanation = "Direct prompt injection patterns found across conversation turns."
    else:
        explanation = "No multi-turn injection patterns detected."

    return {
        "risk_score": risk_score,
        "is_malicious": risk_score >= 40,
        "attack_vector": attack_vector,
        "explanation": explanation,
        "per_turn_analysis": per_turn,
        "total_user_turns": total_turns,
        "priming_detected": priming_detected,
        "escalation_detected": escalation_detected,
        "context_poisoning_detected": poison_detected,
    }
