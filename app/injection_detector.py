import re
from dataclasses import dataclass
from typing import List

@dataclass
class InjectionResult:
    detected: bool
    score: float        # 0.0 -> 1.0
    patterns_hit: List[str]

# -------- Pattern groups --------
# Mỗi group là một kiểu tấn công khác nhau
PATTERNS = {
    "role_switch": [
        r"(?i)(ignore|forget|disregard).{0,30}(previous|prior|above|all).{0,30}(instruction|prompt|rule|constraint)",
        r"(?i)you are now\b",
        r"(?i)pretend (you are|to be|you're)\b",
        r"(?i)act as (an? )?(unrestricted|unfiltered|evil|dan|jailbreak)",
        r"(?i)\bDAN\b.{0,20}(mode|prompt|jailbreak)",
    ],
    "system_leak": [
        r"(?i)(reveal|show|print|output|display|repeat|tell me).{0,30}(system prompt|initial prompt|instruction|confidential)",
        r"(?i)what (is|are|were) (your|the) (system|original|initial|hidden) (prompt|instruction)",
        r"(?i)(leak|expose|dump).{0,20}(prompt|instruction|config|secret)",
    ],
    "override_attempt": [
        r"(?i)(new|updated|override|replace).{0,20}(instruction|rule|guideline|policy|prompt)",
        r"(?i)from now on (you|ignore|forget|always|never)",
        r"(?i)(your|all) (previous |prior )?(instruction|rule|limit|restriction|constraint)s? (are )?(void|invalid|lifted|removed|disabled|no longer)",
    ],
    "encoding_trick": [
        r"(?i)(base64|hex|rot13|caesar).{0,30}(decode|encode|translate)",
        r"(?i)translate (this|the following).{0,20}(instruction|command|prompt)",
    ],
    "privilege_escalation": [
        r"(?i)(admin|developer|sudo|root|god|master|owner).{0,20}(mode|access|privilege|override|unlock)",
        r"(?i)maintenance (mode|override|access)",
    ],
}

# Weight của từng group (group nguy hiểm hơn = weight cao hơn)
GROUP_WEIGHTS = {
    "role_switch":           0.40,
    "system_leak":           0.35,
    "override_attempt":      0.30,
    "encoding_trick":        0.25,
    "privilege_escalation":  0.30,
}

def detect_injection(text: str) -> InjectionResult:
    score = 0.0
    patterns_hit = []

    for group_name, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                score += GROUP_WEIGHTS[group_name]
                patterns_hit.append(group_name)
                break  # mỗi group chỉ tính 1 lần dù match nhiều pattern

    # Cap score tối đa là 1.0
    score = min(score, 1.0)

    # Threshold 0.25 — tức là chỉ cần hit 1 group là flag
    return InjectionResult(
        detected=score >= 0.25,
        score=round(score, 2),
        patterns_hit=list(set(patterns_hit))
    )