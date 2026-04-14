from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import time

from app.models import ProxyRequest, Message
from app.inspector import inspect
from app.proxy import forward
from typing import List
from app.logger import log_request
from app.output_inspector import inspect_output

app = FastAPI(title="AI Shield Firewall", version="0.1.0")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

@app.post("/v1/inspect")
async def inspect_only(messages: List[Message]):
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
async def inspect_output_only(payload: dict):
    """Test output inspector độc lập."""
    text = payload.get("text", "")
    result = inspect_output(text)
    return {
        "safe": result.safe,
        "reason": result.reason,
        "filtered_text": result.filtered_text
    }

@app.post("/v1/chat")
async def chat(request: ProxyRequest):
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