from __future__ import annotations

from datetime import timedelta

import pytest
import sysadmin_api.security as security_module
from fastapi.testclient import TestClient

from sysadmin_api.main import SESSION_COOKIE, create_app
from sysadmin_api.repository import InMemoryRepository, SqlRepository
from sysadmin_api.runtime import build_runtime
from sysadmin_api.security import token_hash


def build_client(settings, tmp_path, repository_kind: str):
    repository = (
        InMemoryRepository()
        if repository_kind == "memory"
        else SqlRepository(
            "sqlite:///%s" % (tmp_path / ("%s-auth.db" % repository_kind)),
            create_schema=True,
        )
    )
    runtime = build_runtime(settings, repository=repository)
    client = TestClient(create_app(runtime=runtime))
    return repository, runtime, client


def login(client: TestClient) -> tuple[str, str]:
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert response.status_code == 200
    session_token = client.cookies.get(SESSION_COOKIE)
    assert session_token
    return response.json()["csrfToken"], session_token


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_login_restore_expire_and_reject_stale_csrf(
    settings,
    tmp_path,
    monkeypatch,
    repository_kind,
):
    repository, runtime, client = build_client(settings, tmp_path, repository_kind)
    csrf_token, session_token = login(client)

    restored = TestClient(create_app(runtime=runtime))
    restored.cookies.set(SESSION_COOKIE, session_token)

    me = restored.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "admin"

    without_csrf = client.post(
        "/hosts",
        json={
            "name": "restore-test",
            "address": "10.0.0.44",
            "username": "ubuntu",
        },
    )
    assert without_csrf.status_code == 403

    session = repository.get_session(token_hash(session_token))
    assert session is not None
    future = session["expires_at"] + timedelta(seconds=1)
    monkeypatch.setattr(security_module, "utc_now", lambda: future)

    expired = restored.get("/auth/me")
    assert expired.status_code == 401
    assert repository.get_session(token_hash(session_token)) is None

    expired_csrf = client.post(
        "/hosts",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "expired-test",
            "address": "10.0.0.45",
            "username": "ubuntu",
        },
    )
    assert expired_csrf.status_code == 401


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_logout_invalidates_server_session_and_browser_cookie(
    settings,
    tmp_path,
    repository_kind,
):
    repository, _, client = build_client(settings, tmp_path, repository_kind)
    csrf_token, session_token = login(client)

    response = client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": csrf_token},
    )

    assert response.status_code == 204
    header = response.headers.get("set-cookie", "")
    assert SESSION_COOKIE in header
    assert "Max-Age=0" in header
    assert repository.get_session(token_hash(session_token)) is None
    assert not client.cookies.get(SESSION_COOKIE)
    assert client.get("/auth/me").status_code == 401
