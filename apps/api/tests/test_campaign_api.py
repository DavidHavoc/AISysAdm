from fastapi.testclient import TestClient

from sysadmin_api.main import create_app
from sysadmin_api.repository import InMemoryRepository
from sysadmin_api.runtime import build_runtime

from test_api import login


def create_host(client, csrf, name):
    response = client.post(
        "/hosts",
        headers={"X-CSRF-Token": csrf},
        json={
            "name": name,
            "address": "10.0.0.20",
            "username": "ubuntu",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_campaign_api_keeps_approval_per_host(settings):
    runtime = build_runtime(settings, repository=InMemoryRepository())
    client = TestClient(create_app(runtime=runtime))
    csrf = login(client)
    headers = {"X-CSRF-Token": csrf}
    first = create_host(client, csrf, "api-web-1")
    second = create_host(client, csrf, "api-web-2")

    created = client.post(
        "/campaigns",
        headers=headers,
        json={
            "name": "API patch wave",
            "hostIds": [first["id"], second["id"]],
        },
    )
    assert created.status_code == 201
    campaign_id = created.json()["id"]

    proposals = client.post(
        "/campaigns/%s/proposals" % campaign_id,
        headers=headers,
    )
    assert proposals.status_code == 202
    campaign = proposals.json()["campaign"]
    first_plan = next(
        item for item in campaign["hosts"] if item["hostId"] == first["id"]
    )

    wrong_hostname = client.post(
        "/campaigns/%s/hosts/%s/approve" % (campaign_id, first["id"]),
        headers=headers,
        json={
            "planVersion": first_plan["planVersion"],
            "planHash": first_plan["planHash"],
            "hostnameConfirmation": second["name"],
        },
    )
    assert wrong_hostname.status_code == 400

    approval = {
        "planVersion": first_plan["planVersion"],
        "planHash": first_plan["planHash"],
        "hostnameConfirmation": first["name"],
    }
    assert client.post(
        "/campaigns/%s/hosts/%s/approve" % (campaign_id, first["id"]),
        headers=headers,
        json=approval,
    ).status_code == 200
    assert client.post(
        "/campaigns/%s/hosts/%s/reboot-approval"
        % (campaign_id, first["id"]),
        headers=headers,
        json=approval,
    ).status_code == 200

    executed = client.post(
        "/campaigns/%s/execute" % campaign_id,
        headers=headers,
    )
    assert executed.status_code == 202
    payload = executed.json()
    assert len(payload["jobs"]) == 1
    assert payload["jobs"][0]["hostId"] == first["id"]
    second_plan = next(
        item
        for item in payload["campaign"]["hosts"]
        if item["hostId"] == second["id"]
    )
    assert second_plan["approvalState"] == "pending"
    assert second_plan["state"] == "awaiting_approval"

    assert client.post(
        "/campaigns/%s/approve" % campaign_id,
        headers=headers,
        json=approval,
    ).status_code in (404, 405)
