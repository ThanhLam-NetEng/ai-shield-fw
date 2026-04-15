import boto3
from boto3.dynamodb.conditions import Key
from fastapi.responses import HTMLResponse

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import time

from app.models import ProxyRequest, Message
from app.inspector import inspect
from app.proxy import forward
from typing import List
from app.logger import log_request
from app.output_inspector import inspect_output
from app.policy_engine import invalidate_cache

from app.auth import verify_api_key
from fastapi import Depends

app = FastAPI(title="AI Shield Firewall", version="0.1.0")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

@app.get("/v1/dashboard/stats")
async def dashboard_stats():
    """Trả về stats từ DynamoDB cho dashboard."""
    try:
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.Table("ai-shield-logs")

        # Scan toàn bộ logs
        response = table.scan()
        items = response.get("Items", [])

        # Paginate nếu có nhiều hơn 1MB data
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))

        # Tính stats
        stats = {"BLOCK": 0, "REDACT": 0, "ALLOW": 0}
        recent = []
        violation_types = {}

        for item in items:
            action = item.get("action", "ALLOW")
            stats[action] = stats.get(action, 0) + 1

            reason = item.get("reason", "none")
            if reason != "none":
                violation_types[reason] = violation_types.get(reason, 0) + 1

            recent.append({
                "timestamp": item.get("timestamp", ""),
                "action": action,
                "reason": reason,
                "org_id": item.get("org_id", "default"),
                "preview": item.get("preview", ""),
            })

        # Sort by timestamp descending, lấy 20 cái mới nhất
        recent.sort(key=lambda x: x["timestamp"], reverse=True)
        recent = recent[:20]

        total = sum(stats.values())
        block_rate = round(stats["BLOCK"] / total * 100, 1) if total > 0 else 0

        return {
            "stats": stats,
            "total": total,
            "block_rate": block_rate,
            "recent": recent,
            "violation_types": violation_types,
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Dashboard UI."""
    with open("app/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/v1/inspect")
async def inspect_only(messages: List[Message], api_key: str = Depends(verify_api_key)):
    """Test inspector mà không cần forward đến AI provider."""
    result = inspect(messages, org_id="default")

    # Log request
    log_request(
        action=result.action,
        reason=result.reason,
        org_id="default",
        original_text=messages[-1].content if messages else None,
    )

    return {
        "action": result.action,
        "reason": result.reason,
        "modified_messages": [m.model_dump() for m in result.modified_messages] if result.modified_messages else None
    }

@app.post("/v1/inspect-output")
async def inspect_output_only(payload: dict, api_key: str = Depends(verify_api_key)):
    """Test output inspector độc lập."""
    text = payload.get("text", "")
    result = inspect_output(text)
    return {
        "safe": result.safe,
        "reason": result.reason,
        "filtered_text": result.filtered_text
    }

@app.post("/v1/chat")
async def chat(request: ProxyRequest, api_key: str = Depends(verify_api_key)):
    start = time.time()

    # Step 1: Inspect
    result = inspect(request.messages, org_id=request.org_id)
    # Log mọi request
    log_request(
        action=result.action,
        reason=result.reason,
        org_id=request.org_id,
        original_text=request.messages[-1].content if request.messages else None,
    )
    shield_info = {
        "action": result.action,
        "reason": result.reason,
        "latency_ms": None
    }

    if result.action == "BLOCK":
        shield_info["latency_ms"] = round((time.time() - start) * 1000, 2)
        return JSONResponse(
            status_code=403,
            content={"error": "Request blocked by AI Shield", **shield_info}
        )

    if result.action == "REDACT" and result.modified_messages:
        request.messages = result.modified_messages

    # Step 2: Forward
    try:
        response = await forward(request)
    except Exception as e:
        shield_info["latency_ms"] = round((time.time() - start) * 1000, 2)
        return JSONResponse(
            status_code=502,
            content={
                "shield": shield_info,
                "error": f"Upstream error: {str(e)[:200]}"
            }
        )

    shield_info["latency_ms"] = round((time.time() - start) * 1000, 2)

    # Output inspection
    try:
        # Lấy text response từ OpenAI hoặc Gemini
        if request.provider == "openai":
            ai_text = response["choices"][0]["message"]["content"]
        elif request.provider == "gemini":
            ai_text = response["candidates"][0]["content"]["parts"][0]["text"]
        else:
            ai_text = ""

        output_check = inspect_output(ai_text)
        shield_info["output_safe"] = output_check.safe

        if not output_check.safe:
            shield_info["output_reason"] = output_check.reason
            if request.provider == "openai":
                response["choices"][0]["message"]["content"] = output_check.filtered_text
            elif request.provider == "gemini":
                response["candidates"][0]["content"]["parts"][0]["text"] = output_check.filtered_text
    except Exception:
        pass  # Không để output inspection crash server

    return {"shield": shield_info, "response": response}

@app.post("/v1/admin/reload-policy")
async def reload_policy(api_key: str = Depends(verify_api_key)):
    """Reload policy cache từ DynamoDB."""
    invalidate_cache()
    return {"status": "policy cache cleared"}
