import base64
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
    app_environment: str = "development"
    app_base_url: str = "http://localhost:8080"
    cookie_secure: bool = False
    session_ttl_hours: int = 12
    admin_username: str = "admin"
    admin_password: Optional[str] = None
    admin_password_file: Optional[Path] = None
    encryption_key: Optional[str] = None
    encryption_key_file: Optional[Path] = None
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )

    database_url: Optional[str] = None
    redis_url: Optional[str] = None
    agent_memory_ttl_seconds: int = 3600
    celery_task_always_eager: bool = False
    log_retention_days: int = 90

    collector_mode: str = "demo"
    execution_mode: str = "simulate"
    data_dir: Path = Path(".data")
    ansible_playbook_dir: Path = Path("ops/ansible/playbooks")
    ansible_callback_dir: Path = Path("ops/ansible/callback_plugins")
    agent_contract_dir: Path = Path("agents")
    max_evidence_bytes_per_source: int = 65536
    diagnostic_window_hours: int = 24

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

    def read_secret(self, value: Optional[str], path: Optional[Path]) -> Optional[str]:
        if path and path.exists():
            return path.read_text(encoding="utf-8").strip()
        return value

    @property
    def resolved_admin_password(self) -> Optional[str]:
        return self.read_secret(self.admin_password, self.admin_password_file)

    @property
    def resolved_encryption_key(self) -> Optional[bytes]:
        value = self.read_secret(self.encryption_key, self.encryption_key_file)
        if not value:
            return None
        try:
            decoded = base64.urlsafe_b64decode(value.encode("ascii"))
        except Exception as error:
            raise ValueError("ENCRYPTION_KEY must be URL-safe base64") from error
        if len(decoded) != 32:
            raise ValueError("ENCRYPTION_KEY must decode to exactly 32 bytes")
        return decoded

    def validate_runtime_requirements(self) -> None:
        if self.app_environment != "alpha":
            return
        if not self.database_url or not self.database_url.startswith(
            ("postgresql://", "postgresql+psycopg://")
        ):
            raise RuntimeError("Alpha mode requires a PostgreSQL DATABASE_URL")
        if not self.redis_url or not self.redis_url.startswith(
            ("redis://", "rediss://")
        ):
            raise RuntimeError("Alpha mode requires a Redis REDIS_URL")
