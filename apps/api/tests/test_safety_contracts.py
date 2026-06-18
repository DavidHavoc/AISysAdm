from sysadmin_api.contracts import AgentContractLoader
from sysadmin_api.models import AgentName, Host, PatchPolicy, utc_now
from sysadmin_api.redaction import redact_payload


def test_all_agent_contracts_allow_at_most_one_review_round(settings):
    contracts = AgentContractLoader(settings.agent_contract_dir).load_all()

    assert set(contracts) == {
        AgentName.ORCHESTRATOR,
        AgentName.LOG_ANALYST,
        AgentName.LINUX_STATE_ANALYST,
    }
    assert all(item.max_conversation_rounds <= 1 for item in contracts.values())
    assert all(item.content_hash for item in contracts.values())


def test_external_provider_payload_redacts_host_and_identity_evidence():
    now = utc_now()
    host = Host(
        id="host-1",
        name="prod-web-1",
        address="10.0.0.25",
        username="ubuntu",
        patch_policy=PatchPolicy(),
        created_at=now,
        updated_at=now,
    )
    payload = {
        "host": host.model_dump(mode="json"),
        "auth": "admin@example.com from 10.0.0.25 on prod-web-1 as ubuntu",
        "private_key": "secret material",
    }

    redacted = redact_payload(payload, host)
    rendered = str(redacted)

    assert "prod-web-1" not in rendered
    assert "10.0.0.25" not in rendered
    assert "admin@example.com" not in rendered
    assert "secret material" not in rendered
