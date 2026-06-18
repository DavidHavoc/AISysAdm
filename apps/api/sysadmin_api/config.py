from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_host: str = "0.0.0.0"
    api_port: int = 4000
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    database_url: Optional[str] = None
    redis_url: Optional[str] = None
    agent_memory_ttl_seconds: int = 3600

    collector_mode: str = "demo"
    execution_mode: str = "simulate"
    data_dir: Path = Path(".data")
    ansible_playbook_dir: Path = Path("ops/ansible/playbooks")

    ai_provider_order: str = "openai,anthropic,ollama"
    ai_orchestrator_provider: str = "auto"
    ai_specialist_provider: str = "auto"

    openai_api_key: Optional[str] = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_strong_model: Optional[str] = None
    openai_economy_model: Optional[str] = None

    anthropic_api_key: Optional[str] = None
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    anthropic_strong_model: Optional[str] = None
    anthropic_economy_model: Optional[str] = None

    ollama_base_url: str = "http://localhost:11434"
    ollama_strong_model: Optional[str] = None
    ollama_economy_model: Optional[str] = None

    @property
    def provider_order(self) -> List[str]:
        return [item.strip() for item in self.ai_provider_order.split(",") if item.strip()]
