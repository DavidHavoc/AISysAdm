from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from redis import Redis

from .agents import MultiAgentWorkflow
from .authorization import AlphaAuthorizationPolicy, AuthorizationPolicy
from .collector import DemoCollector, SshCollector
from .config import Settings
from .contracts import AgentContractLoader
from .credentials import CredentialService
from .executor import AnsibleExecutor, SimulatedExecutor
from .memory import InMemoryAgentMemory, RedisAgentMemory
from .providers import ModelRouter
from .repository import Repository, SqlRepository
from .security import AuthService, LoginRateLimiter
from .service import SysadminService
from .snapshots import AnsibleSnapshotProvider, SimulatedSnapshotProvider


@dataclass
class Runtime:
    settings: Settings
    repository: Repository
    redis_client: Optional[Redis]
    credentials: CredentialService
    auth: AuthService
    authorization: AuthorizationPolicy
    service: SysadminService


def build_runtime(
    settings: Optional[Settings] = None,
    repository: Optional[Repository] = None,
) -> Runtime:
    resolved = settings or Settings()
    resolved.validate_runtime_requirements()
    repo = repository or build_repository(resolved)
    encryption_key = resolved.resolved_encryption_key
    if encryption_key is None:
        if resolved.app_environment == "alpha":
            raise RuntimeError("Alpha mode requires ENCRYPTION_KEY or ENCRYPTION_KEY_FILE")
        encryption_key = hashlib.sha256(b"development-only-encryption-key").digest()
    credentials = CredentialService(repo, encryption_key)
    redis_client = (
        Redis.from_url(resolved.redis_url, decode_responses=True)
        if resolved.redis_url
        else None
    )
    memory = (
        RedisAgentMemory(resolved.redis_url, resolved.agent_memory_ttl_seconds)
        if resolved.redis_url
        else InMemoryAgentMemory()
    )
    contracts = AgentContractLoader(resolve_path(resolved.agent_contract_dir))
    router = ModelRouter(resolved)
    workflow = MultiAgentWorkflow(router, memory, contracts)
    collector = (
        SshCollector(credentials, resolved.max_evidence_bytes_per_source)
        if resolved.collector_mode == "ssh"
        else DemoCollector()
    )
    executor = (
        AnsibleExecutor(
            resolve_path(resolved.ansible_playbook_dir),
            resolve_path(resolved.ansible_callback_dir),
            credentials,
        )
        if resolved.execution_mode == "ansible"
        else SimulatedExecutor()
    )
    snapshot_provider = (
        AnsibleSnapshotProvider(
            resolve_path(resolved.ansible_snapshot_playbook_dir),
            resolve_path(resolved.ansible_callback_dir),
            credentials,
        )
        if resolved.execution_mode == "ansible"
        else SimulatedSnapshotProvider()
    )
    auth = AuthService(
        repo,
        resolved.session_ttl_hours,
        LoginRateLimiter(redis_client),
    )
    password = resolved.resolved_admin_password
    if not password:
        if resolved.app_environment == "alpha":
            raise RuntimeError("Alpha mode requires ADMIN_PASSWORD or ADMIN_PASSWORD_FILE")
        password = "admin"
    auth.ensure_admin(resolved.admin_username, password)
    service = SysadminService(
        repository=repo,
        collector=collector,
        workflow=workflow,
        executor=executor,
        snapshot_provider=snapshot_provider,
        log_retention_days=resolved.log_retention_days,
        job_lease_seconds=resolved.job_lease_seconds,
        job_heartbeat_seconds=resolved.job_heartbeat_seconds,
    )
    return Runtime(
        settings=resolved,
        repository=repo,
        redis_client=redis_client,
        credentials=credentials,
        auth=auth,
        authorization=AlphaAuthorizationPolicy(),
        service=service,
    )


def build_repository(settings: Settings) -> Repository:
    if settings.database_url:
        return SqlRepository(
            settings.database_url,
            create_schema=settings.app_environment in ("development", "test"),
        )
    if settings.app_environment == "alpha":
        raise RuntimeError("Alpha mode requires a PostgreSQL DATABASE_URL")
    data_dir = resolve_path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    return SqlRepository(
        "sqlite:///%s" % (data_dir / "development.db"),
        create_schema=True,
    )


def resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    current = Path.cwd()
    candidate = current / path
    if candidate.exists() or current.name != "api":
        return candidate
    return current.parent.parent / path


@lru_cache(maxsize=1)
def get_runtime() -> Runtime:
    return build_runtime()
