from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    openai_api_key: str = ""
    gemini_api_key: str = ""
    app_port: int = 8000
    shield_api_keys: str = "shield-key-demo123"  # default cho dev

    def get_api_keys(self) -> List[str]:
        return [k.strip() for k in self.shield_api_keys.split(",")]

    class Config:
        env_file = ".env"

settings = Settings()