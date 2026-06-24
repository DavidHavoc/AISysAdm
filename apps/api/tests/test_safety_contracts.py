import json

from sysadmin_api.contracts import AgentContractLoader
from sysadmin_api.models import AgentName, Host, PatchPolicy, StructuredLogEvent, utc_now
from sysadmin_api.redaction import (
    redact_payload,
    sanitize_celery_payload,
    sanitize_log_event,
)


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


def test_redaction_handles_nested_objects_and_free_form_strings():
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
        "nested": {
            "authorization": "Bearer sk-test-1234567890ABCDEFGHIJKLMN",
            "password": "hunter2",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "email": "admin@example.com",
            "hostname": "prod-web-1",
            "username": "ubuntu",
            "address": "10.0.0.25",
        },
        "freeform": (
            "Authorization: Bearer sk-test-1234567890ABCDEFGHIJKLMN\n"
            "operator admin@example.com connected to prod-web-1 at 10.0.0.25 "
            "as ubuntu with password=hunter2 and token=ghp_1234567890ABCDEFGHIJKLMN\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
        ),
    }

    redacted = redact_payload(payload, host)
    rendered = json.dumps(redacted, sort_keys=True)

    assert "prod-web-1" not in rendered
    assert "10.0.0.25" not in rendered
    assert "ubuntu" not in rendered
    assert "admin@example.com" not in rendered
    assert "hunter2" not in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in rendered
    assert "[PRIVATE_KEY]" in rendered
    assert "[AUTHORIZATION]" in rendered or "[BEARER_TOKEN]" in rendered
    assert "[PASSWORD]" in rendered
    assert "[API_KEY]" in rendered


def test_structured_log_event_redacts_before_after_and_raw_fields():
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
    event = StructuredLogEvent(
        id="log-1",
        timestamp=now,
        event_type="ansible_process",
        evidence_category="remediation",
        status="failed",
        before_value={"authorization": "Bearer sk-test-1234567890ABCDEFGHIJKLMN"},
        after_value={"password": "super-secret"},
        stdout="prod-web-1 10.0.0.25 ubuntu admin@example.com",
        stderr="-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
        raw_output="token=ghp_1234567890ABCDEFGHIJKLMN",
        correlation_ids={"hostname": "prod-web-1"},
    )

    sanitized = sanitize_log_event(event, host)
    rendered = json.dumps(sanitized.model_dump(mode="json"), sort_keys=True)

    assert sanitized.redacted is True
    assert "prod-web-1" not in rendered
    assert "10.0.0.25" not in rendered
    assert "ubuntu" not in rendered
    assert "admin@example.com" not in rendered
    assert "ghp_1234567890ABCDEFGHIJKLMN" not in rendered
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in rendered


def test_celery_payload_redacts_nested_free_form_errors():
    payload = {
        "job": {
            "error": (
                "Authorization: Bearer sk-test-1234567890ABCDEFGHIJKLMN "
                "email=admin@example.com host=prod-web-1"
            ),
            "last_failure": {
                "message": "token=ghp_1234567890ABCDEFGHIJKLMN",
            },
        }
    }

    redacted = sanitize_celery_payload(payload)
    rendered = json.dumps(redacted, sort_keys=True)

    assert "sk-test-1234567890ABCDEFGHIJKLMN" not in rendered
    assert "admin@example.com" not in rendered
    assert "prod-web-1" not in rendered
    assert "ghp_1234567890ABCDEFGHIJKLMN" not in rendered
