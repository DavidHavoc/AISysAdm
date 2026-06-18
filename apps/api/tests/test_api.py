from fastapi.testclient import TestClient

from sysadmin_api.main import create_app


def test_health_and_host_creation(settings, service):
    client = TestClient(create_app(settings=settings, service=service))

    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["documentation"] == "/docs"
    assert client.get("/favicon.ico").status_code == 204
    assert client.get("/health").json()["ok"] is True
    response = client.post(
        "/hosts",
        json={
            "name": "api-web-1",
            "address": "10.0.0.20",
            "port": 22,
            "username": "ubuntu",
            "distroFamily": "debian",
            "environment": "production",
            "tags": ["web"],
            "criticality": "normal",
            "availabilityClass": "standard",
            "patchPolicy": {
                "updateMode": "orchestrator_decides",
                "executionTiming": "immediate",
                "maxBatchSize": 5,
                "canaryCount": 1,
                "rebootPolicy": "if_required",
            },
        },
    )

    assert response.status_code == 201
    assert response.json()["patchPolicy"]["rebootPolicy"] == "if_required"
