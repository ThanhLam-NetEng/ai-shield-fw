import boto3
from typing import List, Optional
from dataclasses import dataclass, field

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table("ai-shield-policies")

# Cache policy trong RAM, tránh query DB mỗi request
_policy_cache: dict = {}

@dataclass
class OrgPolicy:
    org_id: str
    keyword_blacklist: List[str] = field(default_factory=list)
    max_message_length: int = 2000
    block_after_hours: bool = False

def _load_policy(org_id: str) -> OrgPolicy:
    """Load policy từ DynamoDB, fallback về default nếu không tìm thấy."""
    try:
        resp = table.get_item(Key={"org_id": org_id})
        item = resp.get("Item")
        if not item:
            # Thử load default policy
            resp = table.get_item(Key={"org_id": "default"})
            item = resp.get("Item", {})

        return OrgPolicy(
            org_id=org_id,
            keyword_blacklist=[k.lower() for k in item.get("keyword_blacklist", [])],
            max_message_length=int(item.get("max_message_length", 2000)),
            block_after_hours=bool(item.get("block_after_hours", False)),
        )
    except Exception as e:
        print(f"[WARN] Policy load failed for {org_id}: {e}")
        return OrgPolicy(org_id=org_id)

def get_policy(org_id: str) -> OrgPolicy:
    """Get policy từ cache hoặc load từ DynamoDB."""
    if org_id not in _policy_cache:
        _policy_cache[org_id] = _load_policy(org_id)
    return _policy_cache[org_id]

def invalidate_cache(org_id: Optional[str] = None):
    """Xóa cache khi policy được update."""
    if org_id:
        _policy_cache.pop(org_id, None)
    else:
        _policy_cache.clear()

@dataclass
class PolicyCheckResult:
    passed: bool
    reason: Optional[str] = None

def check_policy(text: str, org_id: str) -> PolicyCheckResult:
    """Kiểm tra text có vi phạm policy của org không."""
    policy = get_policy(org_id)

    # Check message length
    if len(text) > policy.max_message_length:
        return PolicyCheckResult(
            passed=False,
            reason=f"Message exceeds max length ({len(text)}/{policy.max_message_length})"
        )

    # Check keyword blacklist
    text_lower = text.lower()
    for keyword in policy.keyword_blacklist:
        if keyword in text_lower:
            return PolicyCheckResult(
                passed=False,
                reason=f"Blocked keyword detected: '{keyword}'"
            )

    return PolicyCheckResult(passed=True)