# AI Linux Sysadmin

AI Linux Sysadmin is a private-alpha control plane for inspecting Ubuntu and
Debian hosts, producing evidence-backed findings, and running explicitly
approved patch remediations.

The project combines a FastAPI API, Celery workers, PostgreSQL, Redis, a React
operator dashboard, fixed SSH collection commands, and catalog-based Ansible
execution. Safe demo collection and simulated execution are enabled by default.

> This is alpha software. Do not use it as an unattended production
> remediation system.

## Current features

- Authenticated operator dashboard with CSRF-protected mutations
- Login throttling with Redis-backed counters and safe in-process fallback
- Centralized admin-only authorization policy with explicit future role names
- Encrypted SSH credential storage
- Host inventory and connection testing
- Manual and scheduled scans
- Three-agent analysis using Linux state, log analysis, and orchestration roles
- Deterministic local analysis when no AI provider is configured
- Evidence-backed findings with one peer review per specialist result
- Fixed read-only SSH collection catalog
- Approval-gated remediation plans with exact plan version and hash binding
- Hostname confirmation before approval
- Explicit reboot assessment and reboot policy enforcement
- Simulated execution and catalog-based Ansible execution
- Durable PostgreSQL job, scan, finding, remediation, audit, and log records
- Durable job leases, heartbeats, bounded retries, and stale-worker recovery
- Celery workers and Celery Beat backed by Redis
- Atomic job claiming to prevent duplicate execution
- Structured logs, alerts, audit events, and 90-day log retention
- External provider routing with sensitive-value redaction
- PostgreSQL and Redis readiness checks plus expiring worker and Beat health markers
- Campaign proposals, per-host approvals, execution, cancellation, and results

## Safety model

The control plane does not allow an AI provider to invent shell commands or
directly execute changes. Collection and remediation use predefined catalogs.

A remediation can run only when:

1. An operator approves the exact plan version and hash.
2. The operator confirms the target hostname.
3. The plan remains unchanged after approval.
4. Reboot approval and the host reboot policy permit any required reboot.
5. The executor independently validates the approval immediately before work.

Scheduled scans may produce findings and remediation proposals, but they never
approve or execute a remediation. Unsupported provider claims are excluded from
findings and plans. Deterministic conflicts and evidence requirements cannot be
removed by a provider response.

The current threat model is documented in
[`docs/threat-model.md`](docs/threat-model.md).

## Architecture

```text
React dashboard
      |
FastAPI API
      |
PostgreSQL + Redis
      |
Celery worker + Celery Beat
      |
SSH collector / Ansible executor
```

The analysis workflow has three roles:

- **Linux State Analyst:** evaluates packages, services, resources, kernel
  state, uptime, and package-manager health.
- **Log Analyst:** evaluates journal, authentication, kernel, boot, service,
  and package history evidence.
- **Orchestrator:** combines verified specialist results and creates a
  policy-constrained remediation proposal.

The versioned role contracts are stored in [`agents/`](agents/).

## Requirements

- Python 3.9 or newer
- Node.js with npm
- Docker with Compose, or separately managed PostgreSQL and Redis instances
- Ansible on the control-plane host for real execution

PostgreSQL and Redis are mandatory when `APP_ENVIRONMENT=alpha`. SQLite and
inline jobs are available only as development and test conveniences.

## Local setup

Install the application dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e "apps/api[dev]"
npm install
```

Create the local configuration and start PostgreSQL and Redis:

```bash
cp .env.example .env
docker compose up -d postgres redis
```

Set these required values in `.env`:

```text
ADMIN_PASSWORD=<strong password>
ENCRYPTION_KEY=<URL-safe base64 encoding of exactly 32 random bytes>
```

In `APP_ENVIRONMENT=alpha`, cookies must be marked secure unless the control
plane is running on `localhost`, `127.0.0.1`, or `::1` and the explicit
localhost exception remains enabled:

```text
COOKIE_SECURE=true
ALLOW_INSECURE_LOCALHOST_ALPHA_COOKIES=true
```

The localhost exception keeps local alpha testing and integration work from
breaking silently, but it is only intended for loopback development.

One way to generate the encryption key is:

```bash
python3 -c 'import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Apply the database migrations:

```bash
.venv/bin/alembic upgrade head
```

Run each process in a separate terminal:

```bash
npm run dev:api
.venv/bin/celery -A sysadmin_api.tasks:celery_app worker --loglevel=INFO
.venv/bin/celery -A sysadmin_api.tasks:celery_app beat --loglevel=INFO
npm run dev:web
```

Open:

- Dashboard: <http://localhost:5173>
- API documentation: <http://localhost:4000/docs>
- Readiness: <http://localhost:4000/health/ready>

## Demo and real-host modes

The default configuration does not contact or change real hosts:

```text
COLLECTOR_MODE=demo
EXECUTION_MODE=simulate
```

To use a real host:

1. Upload an SSH private key through the dashboard or `POST /credentials`.
2. Assign the returned credential ID to a host.
3. Install Ansible on the control-plane machine.
4. Set the following values in `.env`:

```text
COLLECTOR_MODE=ssh
EXECUTION_MODE=ansible
```

Test this path only against disposable hosts first. The bundled encrypted
credential vault is intended for private-alpha use, not as a replacement for a
managed production secret store.

## Optional AI providers

OpenAI, Anthropic, and Ollama adapters are available. Model names are
operator-supplied because availability and pricing change over time.

Configure provider credentials and model names in `.env`. Routing follows
`AI_PROVIDER_ORDER`, unless a provider is selected explicitly for orchestration
or specialist work. Provider inputs are redacted before transmission.

When no provider is configured, all roles use deterministic local policy
analysis.

## Development

Run the complete test suite:

```bash
npm test
```

Build the API bytecode, shared TypeScript package, and dashboard:

```bash
npm run build
```

Run only the API tests:

```bash
.venv/bin/pytest -q -m "not integration" apps/api/tests
```

## PostgreSQL and Redis integration tests

The integration suite uses PostgreSQL and Redis, never SQLite. Its Compose
project is isolated from the development stack and binds only to localhost:

- PostgreSQL: `127.0.0.1:55432`
- Redis: `127.0.0.1:56379`, database 15

The test stack uses PostgreSQL trust authentication and fixed application test
values. These values are local test fixtures, not production secrets. Database
and Redis data live in container tmpfs mounts and are removed during cleanup.

Start a fresh stack and apply Alembic migrations:

```bash
./scripts/integration.sh start
```

Run the integration suite. This recreates the stack and reapplies migrations
before testing:

```bash
./scripts/integration.sh test
```

Run the suite and always clean up afterward:

```bash
./scripts/integration.sh verify
```

Run the opt-in real-host suite against disposable Docker SSH targets:

```bash
./scripts/integration.sh real-host
```

This suite requires local SSH tools and `ansible-playbook`. It generates a
test-only SSH key under `.data/integration/real-host`, starts a disposable
Ubuntu SSH target on `127.0.0.1:52222`, and uses `COLLECTOR_MODE=ssh` plus
`EXECUTION_MODE=ansible`. Do not point these tests at production hosts or at
personal SSH keys. Details, troubleshooting, and VM guidance are in
[`docs/real-host-integration.md`](docs/real-host-integration.md).

Remove containers, networks, and volumes:

```bash
./scripts/integration.sh cleanup
```

The integration suite covers:

- Alembic head on a fresh PostgreSQL database
- Atomic job claiming and concurrent worker claims
- Transaction rollback after a PostgreSQL constraint failure
- Healthy readiness plus Redis and PostgreSQL failure reporting
- Ninety-day structured log retention
- Celery task publication and execution through Redis
- Opt-in SSH and Ansible workflows against disposable real hosts

SQLite remains useful for fast repository tests, but it does not reproduce
PostgreSQL row locking, native JSON and timestamp behavior, or Alembic upgrade
execution. In particular, SQLite does not enforce `SELECT FOR UPDATE` locking,
so concurrent job-claim guarantees must be verified with PostgreSQL.

Fast unit tests remain separate and do not require containers:

```bash
npm run test:api
```

## Credential encryption-key rotation

Credential rows are encrypted with one active symmetric key. Live key rotation
is not implemented.

Use a maintenance window for rotation:

1. Stop API writes and background workers.
2. Back up the database and any credential inventory you need to preserve.
3. Re-encrypt credentials under a new `ENCRYPTION_KEY` through an offline
   migration or by re-uploading them after deployment.
4. Update `ENCRYPTION_KEY` or `ENCRYPTION_KEY_FILE` everywhere the API and
   workers run.
5. Restart the control plane and verify credential-backed SSH and Ansible
   actions before resuming operations.

If you change the key without re-encrypting stored credentials, previously
saved SSH keys will no longer decrypt.

## Private-alpha limitations

- Campaign execution controls are not yet enabled in the dashboard. The API
  contract is documented in
  [`docs/frontend-campaign-contract.md`](docs/frontend-campaign-contract.md).
- Login throttling falls back to per-process memory if Redis is unavailable, so
  multi-process coordination is temporarily reduced until Redis recovers.
- SQLite remains a development convenience and cannot verify PostgreSQL row
  locking, `SELECT FOR UPDATE`, or lease-timing behavior.
- Snapshot and rollback provider integrations are deferred.
- The dashboard does not yet expose every API workflow.
- Authentication currently targets a single private-alpha administrator.
- Docker-backed SSH and Ansible integration coverage exists for disposable
  targets. Full VM, systemd reboot, package mirror, and rollback coverage is
  still incomplete.
- Deployment packaging, backup and restore automation, and production
  hardening are not complete.

## License

Copyright (C) 2026 AI Linux Sysadmin contributors

This project is licensed under the GNU Affero General Public License,
version 3. See [`LICENSE`](LICENSE).
