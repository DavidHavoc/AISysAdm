from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest
from redis import Redis
from sqlalchemy import text

from sysadmin_api.config import Settings
from sysadmin_api.database import Base
from sysadmin_api.repository import SqlRepository
from sysadmin_api.runtime import Runtime, build_runtime


@dataclass(frozen=True)
class RealHostTarget:
    name: str
    address: str
    port: int
    username: str
    private_key_path: Path

    @property
    def private_key(self) -> bytes:
        return self.private_key_path.read_bytes()

    def ssh(self, command: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-i",
                str(self.private_key_path),
                "-p",
                str(self.port),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "%s@%s" % (self.username, self.address),
                command,
            ],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


@pytest.fixture(scope="session")
def integration_database_url() -> str:
    value = os.getenv("INTEGRATION_DATABASE_URL")
    if not value:
        pytest.skip("INTEGRATION_DATABASE_URL is required")
    return value


@pytest.fixture(scope="session")
def integration_redis_url() -> str:
    value = os.getenv("INTEGRATION_REDIS_URL")
    if not value:
        pytest.skip("INTEGRATION_REDIS_URL is required")
    return value


@pytest.fixture
def repository(integration_database_url: str) -> Iterator[SqlRepository]:
    repo = SqlRepository(integration_database_url)
    table_names = ", ".join(
        repo.engine.dialect.identifier_preparer.quote(table.name)
        for table in reversed(Base.metadata.sorted_tables)
    )
    with repo.engine.begin() as connection:
        connection.execute(text("TRUNCATE TABLE %s RESTART IDENTITY CASCADE" % table_names))
    try:
        yield repo
    finally:
        repo.engine.dispose()


@pytest.fixture
def redis_client(integration_redis_url: str) -> Iterator[Redis]:
    client = Redis.from_url(
        integration_redis_url,
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    client.flushdb()
    try:
        yield client
    finally:
        client.flushdb()
        client.close()


@pytest.fixture
def integration_settings(
    integration_database_url: str,
    integration_redis_url: str,
) -> Settings:
    repository_root = Path(__file__).resolve().parents[4]
    return Settings(
        app_environment="alpha",
        database_url=integration_database_url,
        redis_url=integration_redis_url,
        admin_username="integration-admin",
        admin_password="integration-test-password",
        encryption_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        collector_mode="demo",
        execution_mode="simulate",
        agent_contract_dir=repository_root / "agents",
        openai_api_key=None,
        anthropic_api_key=None,
    )


@pytest.fixture(scope="session")
def repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


@pytest.fixture(scope="session")
def real_host_target(repository_root: Path) -> RealHostTarget:
    if os.getenv("REAL_HOST_INTEGRATION") != "1":
        pytest.skip("REAL_HOST_INTEGRATION=1 is required")
    for tool in ("ssh", "ssh-keyscan", "ssh-keygen", "ansible-playbook"):
        if not shutil.which(tool):
            pytest.skip("%s is required for real-host integration tests" % tool)
    key_path_raw = os.getenv("REAL_HOST_SSH_KEY")
    if not key_path_raw:
        pytest.skip("REAL_HOST_SSH_KEY is required")
    key_path = Path(key_path_raw).expanduser().resolve()
    fixture_key_dir = (repository_root / ".data/integration/real-host").resolve()
    try:
        key_path.relative_to(fixture_key_dir)
    except ValueError:
        pytest.fail(
            "REAL_HOST_SSH_KEY must point under %s to avoid using real credentials"
            % fixture_key_dir
        )
    if not key_path.exists():
        pytest.skip("REAL_HOST_SSH_KEY does not exist: %s" % key_path)
    address = os.getenv("REAL_HOST_ADDRESS", "127.0.0.1")
    if not _is_loopback(address):
        pytest.fail("Real-host integration targets must be exposed on loopback")
    port = int(os.getenv("REAL_HOST_PORT", "52222"))
    username = os.getenv("REAL_HOST_USERNAME", "sysadm")
    target = RealHostTarget(
        name=os.getenv("REAL_HOST_NAME", "ubuntu-ssh"),
        address=address,
        port=port,
        username=username,
        private_key_path=key_path,
    )
    target.ssh("sudo rm -f /var/run/reboot-required /tmp/ai-sysadm-no-updates")
    return target


@pytest.fixture
def real_host_settings(
    integration_database_url: str,
    integration_redis_url: str,
    repository_root: Path,
) -> Settings:
    return Settings(
        app_environment="alpha",
        database_url=integration_database_url,
        redis_url=integration_redis_url,
        admin_username="integration-admin",
        admin_password="integration-test-password",
        encryption_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        collector_mode="ssh",
        execution_mode="ansible",
        ansible_playbook_dir=(
            repository_root / "apps/api/tests/integration/fixtures/ansible_playbooks"
        ),
        ansible_callback_dir=repository_root / "ops/ansible/callback_plugins",
        agent_contract_dir=repository_root / "agents",
        openai_api_key=None,
        anthropic_api_key=None,
        max_evidence_bytes_per_source=512,
        job_lease_seconds=5,
        job_heartbeat_seconds=1,
    )


@pytest.fixture
def real_host_runtime(
    repository: SqlRepository,
    redis_client: Redis,
    real_host_settings: Settings,
) -> Iterator[Runtime]:
    built = build_runtime(real_host_settings, repository=repository)
    assert built.redis_client is not None
    try:
        yield built
    finally:
        built.redis_client.close()


@pytest.fixture
def runtime(
    repository: SqlRepository,
    redis_client: Redis,
    integration_settings: Settings,
) -> Iterator[Runtime]:
    built = build_runtime(integration_settings, repository=repository)
    assert built.redis_client is not None
    try:
        yield built
    finally:
        built.redis_client.close()


def _is_loopback(address: str) -> bool:
    if address in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False
