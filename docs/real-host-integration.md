# Real-Host Integration Tests

These tests exercise SSH collection and Ansible execution against disposable
Ubuntu or Debian targets. They are opt-in because they require Docker, SSH
tools, and Ansible on the control-plane host.

Use disposable targets only. Do not point these tests at production hosts or at
personal SSH keys. The default script generates a test-only key under
`.data/integration/real-host`.

## What The Default Real-Host Suite Covers

- SSH private-key upload and encrypted storage
- Host creation with `credentialId`
- Host key scan, fingerprint return, explicit first-use confirmation, and
  stored fingerprint reuse
- Wrong fingerprint handling
- Attached credential delete conflict
- `COLLECTOR_MODE=ssh` evidence collection from a real SSH target
- Package, service, system, network, journal, kernel, auth, apt, and reboot
  evidence where available
- Evidence state recording for unavailable or truncated sources
- Structured evidence logs and redaction
- Deterministic multi-agent analysis, findings, remediations, agent runs, and
  agent messages
- `EXECUTION_MODE=ansible` against the disposable target
- Catalog phase execution through Ansible with structured callback events
- Pre-patch validation, package metadata refresh fixture, safe no-op package
  path, reboot-required check, and post-patch validation
- Exact plan version, plan hash, and hostname approval checks
- Separate reboot approval when the scan reports reboot risk
- Plan binding recheck before execution
- Host package, service, or reboot drift blocking before Ansible starts
- PostgreSQL job claiming, heartbeat extension, stale lease recovery, retry
  exhaustion, non-retryable safety failure behavior, and sanitized task payloads
- Jobs, scans, findings, remediations, structured logs, alerts, audit events,
  `/health/ready`, and `/health/ops`

## What Remains Fixture-Based

The default Docker target does not run a full systemd boot. The image provides
deterministic wrappers for `apt`, `journalctl`, and `systemctl` so the suite
can stay fast and local. The Ansible playbooks used by the test runtime live in
`apps/api/tests/integration/fixtures/ansible_playbooks` and use the same catalog
filenames as production playbooks, but package changes are controlled no-ops.

Full systemd behavior, actual reboot execution, real package mirror behavior,
and VM-level rollback or snapshot coverage should be tested separately with
ephemeral VMs exposed through loopback SSH port forwarding.

## Requirements

- Docker with Compose
- Local `ssh`, `ssh-keygen`, and `ssh-keyscan`
- Local `ansible-playbook`
- The project Python virtualenv with `apps/api[dev]` installed

Install Ansible with your operating system package manager or a Python toolchain
that is separate from production secrets. For example:

```bash
python3 -m pip install ansible-core
```

## Run Normal Integration Tests

Normal PostgreSQL and Redis integration tests do not start SSH targets and do
not run the real-host markers:

```bash
./scripts/integration.sh test
```

The npm alias is:

```bash
npm run test:integration
```

## Run Real-Host Integration Tests

Run the Docker-backed real-host suite:

```bash
./scripts/integration.sh real-host
```

The npm alias is:

```bash
npm run test:integration:real-host
```

Run and always clean up afterward:

```bash
./scripts/integration.sh verify-real-host
```

The script starts PostgreSQL, Redis, and a disposable Ubuntu SSH target. It
exports:

```text
REAL_HOST_INTEGRATION=1
REAL_HOST_ADDRESS=127.0.0.1
REAL_HOST_PORT=52222
REAL_HOST_USERNAME=sysadm
REAL_HOST_SSH_KEY=.data/integration/real-host/id_ed25519
COLLECTOR_MODE=ssh
EXECUTION_MODE=ansible
```

The pytest fixture refuses non-loopback target addresses and refuses key paths
outside `.data/integration/real-host`.

## Optional Debian Target

`compose.integration.yaml` also defines a Debian SSH target under the
`real-host-debian` profile on `127.0.0.1:52223`. It is not started by the
default real-host command. Use it for local exploratory coverage or future
parametrized tests.

## VM-Based Coverage

Use VMs when you need full systemd, true reboot behavior, kernel and journal
behavior that Docker cannot model, or package repository behavior that should
not be mocked.

Keep the same safety rules:

- Use only ephemeral Ubuntu or Debian VMs.
- Expose SSH through `127.0.0.1` port forwarding.
- Use a test-only SSH key under `.data/integration/real-host`.
- Destroy the VM after the test run.
- Never use a production hostname or a personal private key.

## Cleanup

Remove containers, networks, volumes, and generated integration data:

```bash
./scripts/integration.sh cleanup
rm -rf .data/integration/real-host
```

The cleanup command is safe to run after failed tests.

## Troubleshooting

SSH target does not become reachable:

- Check Docker is running.
- Run `docker compose --project-name aisysadm-integration --file compose.integration.yaml --profile real-host ps`.
- Confirm `ssh-keyscan -p 52222 127.0.0.1` returns a host key.

Host key confirmation fails:

- Run `./scripts/integration.sh cleanup`.
- Remove `.data/integration/real-host`.
- Run `./scripts/integration.sh real-host` again.

Ansible is missing:

- Install `ansible-playbook`.
- Confirm `ansible-playbook --version` works in the same shell.

PostgreSQL or Redis readiness fails:

- Run `./scripts/integration.sh cleanup`.
- Make sure ports `55432` and `56379` are free.
- Run `./scripts/integration.sh start` for the normal stack or
  `./scripts/integration.sh real-host` for the SSH stack.

Cookie or authentication errors in API tests:

- Use the script-provided loopback configuration.
- Confirm the tests log in as `integration-admin` with the integration password.
- Do not mix `localhost` and non-loopback API base URLs for alpha cookie tests.

Package or service evidence differs from expectations:

- Rebuild the disposable image with `./scripts/integration.sh cleanup` followed
  by `./scripts/integration.sh real-host`.
- Check that no local environment variable points tests at a non-default target.
