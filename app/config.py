from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    openai_api_key: str = ""
    gemini_api_key: str = ""
    app_port: int = 8000

    class Config:
        env_file = ".env"

settings = Settings()