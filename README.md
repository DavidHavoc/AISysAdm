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
- Celery workers and Celery Beat backed by Redis
- Atomic job claiming to prevent duplicate execution
- Structured logs, alerts, audit events, and 90-day log retention
- External provider routing with sensitive-value redaction
- PostgreSQL and Redis readiness checks
- Campaign creation and listing

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
.venv/bin/pytest -q
```

## Private-alpha limitations

- Campaigns can be created and listed, but campaign approval and execution are
  not implemented.
- Jobs have atomic claiming, but worker leases, heartbeats, bounded retries,
  and stale-job recovery are not implemented.
- Readiness checks PostgreSQL and Redis, but not worker or Celery Beat health.
- Snapshot and rollback provider integrations are deferred.
- The dashboard does not yet expose every API workflow.
- Authentication currently targets a single private-alpha administrator.
- PostgreSQL, Redis, SSH, Ansible, and Ubuntu VM integration coverage is still
  incomplete.
- Deployment packaging, backup and restore automation, and production
  hardening are not complete.

## License

Copyright (C) 2026 AI Linux Sysadmin contributors

This project is licensed under the GNU Affero General Public License,
version 3. See [`LICENSE`](LICENSE).
