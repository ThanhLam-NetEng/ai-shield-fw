import re
from typing import List
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from app.models import Message, InspectionResult
from app.injection_detector import detect_injection, InjectionResult
from app.policy_engine import check_policy

# Khởi tạo 1 lần khi server start (nặng, không khởi tạo mỗi request)
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# -------- Regex patterns --------
REGEX_PATTERNS = {
    "VN_PHONE": r"\b(0|\+84)(3[2-9]|5[6-9]|7[0-9]|8[0-9]|9[0-9])\d{7}\b",
    "VN_CCCD":  r"\b\d{12}\b",
    "API_KEY":  r"\b(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35})\b",
    "JWT":      r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
    "PASSWORD": r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*\S+",
    "VN_BANK_ACCOUNT": r"\b\d{9,14}\b(?=.{0,20}(ngân hàng|tài khoản|bank|tk))",
    "VN_TAX_CODE":     r"\b\d{10}(-\d{3})?\b(?=.{0,20}(mã số thuế|MST|tax))",
    "VN_SALARY":       r"(?i)(lương|thu nhập|mức lương|salary).{0,20}\d+.{0,10}(triệu|nghìn|đồng|vnđ|vnd)",
}

# Loại nào thì BLOCK hẳn (không redact)
BLOCK_TYPES = {"API_KEY", "JWT", "PASSWORD"}

def _regex_scan(text: str) -> List[dict]:
    """Quét text bằng regex, trả về list findings."""
    findings = []
    for name, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            findings.append({"type": name, "count": len(matches)})
    return findings

def _presidio_scan(text: str) -> List[dict]:
    """Quét text bằng Presidio NLP."""
    results = analyzer.analyze(
        text=text,
        entities=["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"],
        language="en"
    )
    findings = []
    for r in results:
        if r.score >= 0.7:  # chỉ lấy confidence cao
            findings.append({"type": r.entity_type, "score": round(r.score, 2)})
    return findings

def _redact_text(text: str) -> str:
    """Mask PII trong text bằng Presidio."""
    results = analyzer.analyze(
        text=text,
        entities=["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"],
        language="en"
    )
    if not results:
        return text
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text

def inspect(messages: List[Message], org_id: str = "default") -> InspectionResult:
    all_findings = []

    for msg in messages:
        text = msg.content

        # Lớp 1: Regex
        regex_hits = _regex_scan(text)
        all_findings.extend(regex_hits)

        # Lớp 2: Presidio
        presidio_hits = _presidio_scan(text)
        all_findings.extend(presidio_hits)

        # Lớp 3: Prompt Injection
        injection = detect_injection(text)
        if injection.detected:
            all_findings.append({
                "type": "PROMPT_INJECTION",
                "score": injection.score,
                "patterns": injection.patterns_hit
            })
        
        # Lớp 4: Policy Engine
        policy_check = check_policy(text, org_id=org_id)
        if not policy_check.passed:
            all_findings.append({
                "type": "POLICY_VIOLATION",
                "reason": policy_check.reason
            })

    if not all_findings:
        return InspectionResult(action="ALLOW")

    found_types = {f["type"] for f in all_findings}

    # Tất cả các type này đều BLOCK
    BLOCK_TYPES_ALL = {"API_KEY", "JWT", "PASSWORD", "PROMPT_INJECTION", "POLICY_VIOLATION"}

    if found_types & BLOCK_TYPES_ALL:
        blocked = found_types & BLOCK_TYPES_ALL
        return InspectionResult(
            action="BLOCK",
            reason=f"Sensitive data detected: {', '.join(blocked)}"
        )

    # Còn lại → REDACT
    modified = []
    for msg in messages:
        new_content = _redact_text(msg.content)
        for name, pattern in REGEX_PATTERNS.items():
            if name not in BLOCK_TYPES_ALL:
                new_content = re.sub(pattern, f"[{name}_REDACTED]", new_content)
        modified.append(Message(role=msg.role, content=new_content))

    return InspectionResult(
        action="REDACT",
        reason=f"PII detected and masked: {', '.join(found_types)}",
        modified_messages=modified
    )