import pytest
from fastapi.testclient import TestClient

from sysadmin_api.main import create_app
from sysadmin_api.repository import InMemoryRepository
from sysadmin_api.runtime import build_runtime


def login(client: TestClient):
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert response.status_code == 200
    return response.json()["csrfToken"]


def test_authentication_and_csrf_gate_mutations(settings):
    runtime = build_runtime(settings, repository=InMemoryRepository())
    client = TestClient(create_app(runtime=runtime))

    assert client.get("/hosts").status_code == 401
    csrf = login(client)

    response = client.post(
        "/hosts",
        headers={"X-CSRF-Token": csrf},
        json={
            "name": "api-web-1",
            "address": "10.0.0.20",
            "username": "ubuntu",
        },
    )

    assert response.status_code == 201
    assert response.json()["patchPolicy"]["rebootPolicy"] == "if_required"
    assert client.post("/hosts", json=response.json()).status_code == 403


def test_readiness_reports_missing_redis(settings):
    runtime = build_runtime(settings, repository=InMemoryRepository())
    client = TestClient(create_app(runtime=runtime))

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["database"] is True
    assert response.json()["detail"]["redis"] is False


def test_alpha_requires_postgresql_and_redis(settings):
    settings.app_environment = "alpha"
    settings.database_url = "sqlite:///alpha.db"
    settings.redis_url = None

    with pytest.raises(RuntimeError, match="PostgreSQL"):
        settings.validate_runtime_requirements()

    settings.database_url = "postgresql+psycopg://user:pass@localhost/db"
    with pytest.raises(RuntimeError, match="Redis"):
        settings.validate_runtime_requirements()


def test_campaign_api_requires_per_host_exact_approvals(settings):
    runtime = build_runtime(settings, repository=InMemoryRepository())
    client = TestClient(create_app(runtime=runtime))
    csrf = login(client)
    headers = {"X-CSRF-Token": csrf}

    host_response = client.post(
        "/hosts",
        headers=headers,
        json={
            "name": "api-web-1",
            "address": "10.0.0.20",
            "username": "ubuntu",
        },
    )
    host = host_response.json()
    campaign_response = client.post(
        "/campaigns",
        headers=headers,
        json={"name": "API patch wave", "hostIds": [host["id"]]},
    )
    assert campaign_response.status_code == 201
    campaign = campaign_response.json()

    proposals = client.post(
        "/campaigns/%s/proposals" % campaign["id"],
        headers=headers,
    )
    assert proposals.status_code == 202
    campaign = proposals.json()["campaign"]
    host_plan = campaign["hosts"][0]
    approval = {
        "planVersion": host_plan["planVersion"],
        "planHash": host_plan["planHash"],
        "hostnameConfirmation": "wrong-host",
    }

    wrong_hostname = client.post(
        "/campaigns/%s/hosts/%s/approve" % (campaign["id"], host["id"]),
        headers=headers,
        json=approval,
    )
    assert wrong_hostname.status_code == 400

    approval["hostnameConfirmation"] = host["name"]
    approved = client.post(
        "/campaigns/%s/hosts/%s/approve" % (campaign["id"], host["id"]),
        headers=headers,
        json=approval,
    )
    assert approved.status_code == 200
    assert approved.json()["hosts"][0]["state"] == "awaiting_reboot_approval"

    reboot_approved = client.post(
        "/campaigns/%s/hosts/%s/reboot-approval"
        % (campaign["id"], host["id"]),
        headers=headers,
        json=approval,
    )
    assert reboot_approved.status_code == 200
    assert reboot_approved.json()["hosts"][0]["state"] == "approved"

    blanket = client.post(
        "/campaigns/%s/approve" % campaign["id"],
        headers=headers,
        json=approval,
    )
    assert blanket.status_code == 404

    executed = client.post(
        "/campaigns/%s/execute" % campaign["id"],
        headers=headers,
    )
    assert executed.status_code == 202
    assert executed.json()["campaign"]["status"] == "succeeded"
