import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class OutputCheckResult:
    safe: bool
    reason: Optional[str] = None
    filtered_text: Optional[str] = None

# Patterns nguy hiểm trong response
DANGEROUS_OUTPUT_PATTERNS = {
    "system_prompt_leak": [
        r"(?i)(my system prompt|my instructions are|i (was|am) instructed to|i (was|am) told to)",
        r"(?i)(the system prompt|initial prompt|hidden instruction)",
    ],
    "secret_in_response": [
        r"\b(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35})\b",
        r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
    ],
}

def inspect_output(text: str) -> OutputCheckResult:
    for group_name, patterns in DANGEROUS_OUTPUT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                return OutputCheckResult(
                    safe=False,
                    reason=f"Dangerous content in AI response: {group_name}",
                    filtered_text="[Response blocked by AI Shield — potential data leak detected]"
                )
    return OutputCheckResult(safe=True, filtered_text=text)