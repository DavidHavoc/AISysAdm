from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

import pytest
from redis import Redis
from sqlalchemy import text

from sysadmin_api.config import Settings
from sysadmin_api.database import Base
from sysadmin_api.repository import SqlRepository
from sysadmin_api.runtime import Runtime, build_runtime


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
