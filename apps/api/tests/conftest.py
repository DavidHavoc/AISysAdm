from pathlib import Path

import pytest

from sysadmin_api.agents import MultiAgentWorkflow
from sysadmin_api.collector import DemoCollector
from sysadmin_api.config import Settings
from sysadmin_api.contracts import AgentContractLoader
from sysadmin_api.executor import SimulatedExecutor
from sysadmin_api.memory import InMemoryAgentMemory
from sysadmin_api.providers import ModelRouter
from sysadmin_api.repository import InMemoryRepository
from sysadmin_api.service import SysadminService


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    repository_root = Path(__file__).resolve().parents[3]
    return Settings(
        data_dir=tmp_path,
        database_url=None,
        redis_url=None,
        agent_contract_dir=repository_root / "agents",
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
    workflow = MultiAgentWorkflow(
        router,
        memory,
        AgentContractLoader(settings.agent_contract_dir),
    )
    return SysadminService(
        repository=repository,
        collector=DemoCollector(),
        workflow=workflow,
        executor=SimulatedExecutor(),
    )
