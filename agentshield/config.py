"""Application settings for AgentShield."""
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)
    agentshield_env: str = "development"
    agentshield_debug: bool = True
    agentshield_db_path: str = "./agentshield.db"
    agentshield_output_dir: str = "./reports"
    agentshield_log_level: str = "INFO"
    # When set, the web API requires this token via `Authorization: Bearer <token>`
    # or `X-API-Key`. Empty = auth disabled (local development only).
    agentshield_api_token: str = ""
    # Comma-separated list of allowed CORS origins for the web API.
    agentshield_cors_origins: str = "http://localhost:5173,http://localhost:3000"
    # Semantic confirmation tier: context-aware disposition over static rule candidates.
    # Default on — it raises precision (fewer prose false positives) while staying recall-safe.
    agentshield_semantic_enabled: bool = True
    # "deterministic" (default, offline, no cost) or "llm" (escalate uncertain cases to an LLM;
    # requires OPENAI_API_KEY/CLAUDE_API_KEY). The LLM tier is off unless explicitly selected.
    agentshield_semantic_backend: str = "deterministic"
    # Max LLM confirmation calls per scan when backend="llm" (cost cap).
    agentshield_semantic_llm_budget: int = 20
    claude_api_key: str = ""
    openai_api_key: str = ""

settings = Settings()
