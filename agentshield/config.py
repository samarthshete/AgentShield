"""Application settings for AgentShield."""
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)
    agentshield_env: str = "development"
    agentshield_debug: bool = True
    agentshield_db_path: str = "./agentshield.db"
    agentshield_output_dir: str = "./reports"
    agentshield_log_level: str = "INFO"
    claude_api_key: str = ""
    openai_api_key: str = ""

settings = Settings()
