import boto3
import uuid
from datetime import datetime, timezone

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table("ai-shield-logs")

def log_request(
    action: str,
    reason: str = None,
    org_id: str = "default",
    original_text: str = None,
):
    try:
        table.put_item(Item={
            "log_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "reason": reason or "none",
            "org_id": org_id,
            "preview": original_text[:100] if original_text else "",
        })
    except Exception as e:
        # Không để lỗi log làm crash server
        print(f"[WARN] DynamoDB log failed: {e}")