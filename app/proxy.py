import httpx
from app.models import ProxyRequest
from app.config import settings

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

async def forward_to_openai(request: ProxyRequest) -> dict:
    payload = {
        "model": request.model or "gpt-4o-mini",
        "messages": [m.model_dump() for m in request.messages]
    }
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json"
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(OPENAI_URL, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

async def forward_to_gemini(request: ProxyRequest) -> dict:
    model = request.model or "gemini-2.0-flash"
    url = GEMINI_URL.format(model=model) + f"?key={settings.gemini_api_key}"
    # Convert OpenAI format -> Gemini format
    contents = [
        {"role": m.role if m.role != "assistant" else "model",
         "parts": [{"text": m.content}]}
        for m in request.messages
    ]
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json={"contents": contents})
        resp.raise_for_status()
        return resp.json()

async def forward(request: ProxyRequest) -> dict:
    if request.provider == "openai":
        return await forward_to_openai(request)
    elif request.provider == "gemini":
        return await forward_to_gemini(request)
    else:
        raise ValueError(f"Unknown provider: {request.provider}")