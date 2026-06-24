from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from sysadmin_api.authorization import AlphaAuthorizationPolicy, ProtectedAction
from sysadmin_api.credentials import CredentialService
from sysadmin_api.main import create_app
from sysadmin_api.models import HostInput, User, UserRole, utc_now
from sysadmin_api.repository import InMemoryRepository, SqlRepository
from sysadmin_api.runtime import build_runtime
from sysadmin_api.security import LoginRateLimiter


VALID_PRIVATE_KEY = b"""-----BEGIN OPENSSH PRIVATE KEY-----
super-secret-private-key
-----END OPENSSH PRIVATE KEY-----"""


def login(client: TestClient) -> str:
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert response.status_code == 200
    return response.json()["csrfToken"]


def build_runtime_with_repository(settings, tmp_path, repository_kind: str):
    repository = (
        InMemoryRepository()
        if repository_kind == "memory"
        else SqlRepository(
            "sqlite:///%s" % (tmp_path / ("%s-security.db" % repository_kind)),
            create_schema=True,
        )
    )
    return build_runtime(settings, repository=repository)


class BrokenRedis:
    def incr(self, key):
        raise RuntimeError("redis unavailable")

    def expire(self, key, ttl):
        raise RuntimeError("redis unavailable")

    def delete(self, key):
        raise RuntimeError("redis unavailable")


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_delete_credential_while_attached_returns_actionable_conflict(
    settings,
    tmp_path,
    repository_kind,
):
    runtime = build_runtime_with_repository(settings, tmp_path, repository_kind)
    credential = runtime.credentials.save_private_key("ops", VALID_PRIVATE_KEY)
    runtime.service.create_host(
        HostInput(
            name="prod-web-1",
            address="10.0.0.25",
            username="ubuntu",
            credential_id=credential.id,
        ),
        "admin",
    )
    client = TestClient(create_app(runtime=runtime))
    csrf_token = login(client)

    response = client.delete(
        "/credentials/%s" % credential.id,
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 409
    assert "prod-web-1" in response.json()["detail"]
    assert "Remove it from those hosts" in response.json()["detail"]
    assert runtime.credentials.list_credentials()[0].id == credential.id


def test_settings_rejects_non_base64_encryption_key(settings):
    settings.encryption_key = "not-base64!"

    with pytest.raises(ValueError, match="URL-safe base64"):
        _ = settings.resolved_encryption_key


def test_settings_rejects_wrong_length_encryption_key(settings):
    settings.encryption_key = base64.urlsafe_b64encode(b"short-key").decode("ascii")

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        _ = settings.resolved_encryption_key


def test_credential_service_rejects_wrong_length_runtime_key():
    with pytest.raises(ValueError, match="32 bytes"):
        CredentialService(InMemoryRepository(), b"too-short")


def test_alpha_requires_secure_cookies_off_localhost(settings):
    settings.app_environment = "alpha"
    settings.database_url = "postgresql+psycopg://user:pass@db.example/internal"
    settings.redis_url = "redis://cache.example:6379/0"
    settings.app_base_url = "http://alpha.example.com"
    settings.cookie_secure = False

    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        settings.validate_runtime_requirements()


def test_alpha_allows_explicit_localhost_cookie_exception(settings):
    settings.app_environment = "alpha"
    settings.database_url = "postgresql+psycopg://user:pass@localhost/internal"
    settings.redis_url = "redis://localhost:6379/0"
    settings.app_base_url = "http://localhost:8080"
    settings.cookie_secure = False

    settings.validate_runtime_requirements()

    assert settings.effective_cookie_secure is False


def test_alpha_authorization_policy_is_admin_only():
    policy = AlphaAuthorizationPolicy()
    now = utc_now()
    admin = User(id="user-admin", username="admin", role=UserRole.ADMIN, created_at=now)
    operator = User(
        id="user-operator",
        username="operator",
        role=UserRole.OPERATOR,
        created_at=now,
    )

    assert policy.authorize(admin, ProtectedAction.MANAGE_HOSTS) is True
    assert policy.authorize(operator, ProtectedAction.MANAGE_HOSTS) is False


def test_login_rate_limiter_falls_back_to_memory_when_redis_fails():
    limiter = LoginRateLimiter(
        redis_client=BrokenRedis(),
        maximum_attempts=2,
        window_seconds=60,
    )

    assert limiter.allow("127.0.0.1:admin") is True
    assert limiter.allow("127.0.0.1:admin") is True
    assert limiter.allow("127.0.0.1:admin") is False

    limiter.reset("127.0.0.1:admin")

    assert limiter.allow("127.0.0.1:admin") is True


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_login_throttling_still_blocks_when_redis_is_unavailable(
    settings,
    tmp_path,
    repository_kind,
):
    runtime = build_runtime_with_repository(settings, tmp_path, repository_kind)
    runtime.auth.rate_limiter = LoginRateLimiter(
        redis_client=BrokenRedis(),
        maximum_attempts=2,
        window_seconds=60,
    )
    client = TestClient(create_app(runtime=runtime))

    for _ in range(2):
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrong-password"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"

    throttled = client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )

    assert throttled.status_code == 401
    assert throttled.json()["detail"] == "Too many login attempts. Try again later."
