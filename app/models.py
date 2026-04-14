from pydantic import BaseModel
from typing import Optional, List

class Message(BaseModel):
    role: str
    content: str

class ProxyRequest(BaseModel):
    provider: str          # "openai" hoặc "gemini"
    model: Optional[str] = None
    messages: List[Message]
    org_id: Optional[str] = "default"

class InspectionResult(BaseModel):
    action: str            # "ALLOW" | "BLOCK" | "REDACT"
    reason: Optional[str] = None
    modified_messages: Optional[List[Message]] = None