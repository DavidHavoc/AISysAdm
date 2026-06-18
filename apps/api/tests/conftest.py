from pathlib import Path

import pytest

from sysadmin_api.agents import LinuxStateAgent, LogAnalysisAgent, OrchestratorAgent
from sysadmin_api.collector import DemoCollector
from sysadmin_api.config import Settings
from sysadmin_api.executor import SimulatedExecutor
from sysadmin_api.memory import InMemoryAgentMemory
from sysadmin_api.providers import ModelRouter
from sysadmin_api.repository import InMemoryRepository
from sysadmin_api.service import SysadminService


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_url=None,
        redis_url=None,
        openai_api_key=None,
        openai_strong_model=None,
        openai_economy_model=None,
        anthropic_api_key=None,
        anthropic_strong_model=None,
        anthropic_economy_model=None,
        ollama_strong_model=None,
        ollama_economy_model=None,
    )


@pytest.fixture
def service(settings: Settings) -> SysadminService:
    repository = InMemoryRepository()
    memory = InMemoryAgentMemory()
    router = ModelRouter(settings)
    return SysadminService(
        repository=repository,
        collector=DemoCollector(),
        log_agent=LogAnalysisAgent(router, memory),
        state_agent=LinuxStateAgent(router, memory),
        orchestrator=OrchestratorAgent(router, memory),
        executor=SimulatedExecutor(),
    )
