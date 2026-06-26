# Architecture

AI Linux Sysadmin is a private-alpha control plane for Linux host inspection,
AI-assisted analysis, approval-gated remediation planning, and durable patch
execution.

The system is designed around one rule: AI can analyze evidence and propose
bounded plans, but it cannot invent shell commands or execute changes directly.
Collection and remediation use fixed catalogs, explicit approvals, durable
records, and executor-side validation.

## System Overview

```text
React operator dashboard
        |
        v
FastAPI API and authorization layer
        |
        v
Sysadmin service domain layer
        |
        +--> PostgreSQL repository
        +--> Redis backed memory, throttling, worker health
        +--> SSH credential vault
        +--> AI analysis workflow
        +--> Celery job dispatch
        |
        v
SSH collector and Ansible executor
```

## Main Components

### Operator Dashboard

Location: `apps/web`

The dashboard is the operator control surface. It handles:

- Login and session restore.
- SSH credential upload and deletion.
- Host creation, editing, deletion, credential assignment, and connection tests.
- Scheduled scan configuration.
- Findings, remediation plans, approvals, execution queueing, and job inspection.
- Campaign proposals, per-host approvals, per-host reboot approvals, execution,
  and cancellation.
- Logs, alerts, audit events, agent runs, and agent messages.

The dashboard talks to the API through `apps/web/src/api.ts`. Shared TypeScript
types are generated from `packages/shared/src/index.ts`.

### API

Location: `apps/api/sysadmin_api/main.py`

FastAPI exposes the HTTP contract for operators and the dashboard. Mutating
routes require CSRF protection and authorization. The API delegates domain
behavior to `SysadminService` rather than embedding workflow logic in route
handlers.

Important route groups:

- `auth`: login, logout, current session.
- `credentials`: SSH key upload, listing, deletion.
- `hosts`: inventory management and connection testing.
- `scans`: manual scan queueing and scan history.
- `remediations`: plan approval, reboot approval, rejection, execution.
- `campaigns`: draft creation, proposals, per-host approval, execution, cancel.
- `jobs`: durable job list and job detail.
- `logs`, `alerts`, `audit-events`: operational evidence.
- `agent-runs`: model activity and agent messages.

### Domain Service

Location: `apps/api/sysadmin_api/service.py`

`SysadminService` owns the control-plane workflow. It coordinates repository
updates, audit events, scan creation, analysis, approval validation, job
creation, campaign synchronization, and execution state transitions.

Core responsibilities:

- Keep host, scan, finding, remediation, campaign, job, log, alert, and audit
  records consistent.
- Bind approvals to exact plan versions and hashes.
- Invalidate approvals when plan content changes.
- Enforce reboot policy before execution.
- Prevent duplicate execution jobs with idempotency keys.
- Move jobs through queued, scheduled, running, completed, failed, and canceled
  states.
- Sync campaign host state from individual remediation state.

### Repository

Location: `apps/api/sysadmin_api/repository.py`

The repository provides durable storage behind a common interface. Development
uses SQLite unless PostgreSQL is configured. Alpha mode requires PostgreSQL.

Persisted records include:

- Users and sessions.
- SSH credentials and encrypted private keys.
- Hosts and schedules.
- Scans, findings, remediations, campaigns, and campaign host plans.
- Durable jobs and leases.
- Structured logs, alerts, audit events, agent runs, and agent messages.

### Runtime Assembly

Location: `apps/api/sysadmin_api/runtime.py`

`build_runtime` wires the system together from settings:

- Repository: PostgreSQL, SQLite for development, or test repository injection.
- Redis: optional in development, required in alpha.
- Credential service: encrypted private key storage.
- Auth service: admin user, session handling, login throttling.
- Authorization policy: admin-only private-alpha policy.
- Agent workflow: provider router, memory, and versioned contracts.
- Collector: demo collector or SSH collector.
- Executor: simulated executor or Ansible executor.

### AI Workflow

Locations:

- `apps/api/sysadmin_api/agents.py`
- `apps/api/sysadmin_api/providers.py`
- `agents/`

The analysis workflow uses three roles:

- Linux State Analyst: package, service, kernel, capacity, and package-manager
  evidence.
- Log Analyst: journal, auth, kernel, boot, service, and package-history
  evidence.
- Orchestrator: combines verified findings into policy-bounded remediation
  proposals.

Role contracts live in `agents/` and are loaded by `AgentContractLoader`.
Provider routing supports OpenAI, Anthropic, Ollama, and deterministic local
fallbacks.

### Collector

Location: `apps/api/sysadmin_api/collector.py`

The collector gathers host state. It has two modes:

- Demo mode: deterministic local data for development.
- SSH mode: fixed read-only SSH collection commands against configured hosts.

The collector does not allow model-generated commands.

### Executor

Location: `apps/api/sysadmin_api/executor.py`

The executor runs approved remediation work. It has two modes:

- Simulated mode: safe local execution for development and tests.
- Ansible mode: catalog-based playbooks from `ops/ansible/playbooks`.

Before execution, the service and executor validate that approvals still match
the current plan version and plan hash.

### Workers

Locations:

- `apps/api/sysadmin_api/queue.py`
- `apps/api/sysadmin_api/tasks.py`

Celery workers process scans, remediations, schedules, maintenance-window job
release, stale-worker recovery, health markers, and log retention. Redis backs
the broker and worker health markers.

## Primary Workflows

### Host Setup

1. Operator uploads an SSH credential.
2. Operator creates a host and assigns the credential.
3. Operator tests the connection.
4. If host key confirmation is required, the dashboard shows the fingerprint
   and requires explicit confirmation before storing it.
5. Host is ready for scans after connection checks pass.

### Scan And Analysis

1. Operator starts a scan manually, or a schedule creates one.
2. A durable scan job is queued.
3. The collector gathers host evidence.
4. Linux State Analyst and Log Analyst evaluate bounded evidence.
5. Orchestrator combines verified claims into findings and remediation plans.
6. Findings, agent runs, agent messages, logs, and proposed remediations are
   persisted.

### Remediation Execution

1. Operator reviews the remediation plan, plan version, plan hash, reboot
   assessment, and failure policy.
2. Operator approves the exact patch plan by typing the hostname.
3. If reboot risk is possible, operator separately approves reboot risk by
   typing the hostname again.
4. The dashboard shows blockers until all execution prerequisites are met.
5. Operator types the hostname to queue execution.
6. API creates a durable remediation job using an idempotency key bound to the
   remediation ID and plan hash.
7. Worker executes the approved job.
8. Structured logs, result phases, alerts, audit events, and job status are
   persisted.

### Campaign Execution

1. Operator creates a campaign draft with selected hosts.
2. Operator creates proposals for each campaign host.
3. Each host plan is reviewed independently.
4. Each host patch plan is approved independently with typed hostname
   confirmation.
5. If a host requires reboot approval, the second approval is also per host.
6. Only approved hosts are queued when campaign execution starts.
7. Queued or scheduled campaign work can be canceled.
8. Campaign host states remain authoritative for mixed outcomes.

## Safety Boundaries

The safety model relies on multiple independent gates:

- AI providers cannot execute commands.
- Collection and remediation use fixed catalogs.
- Approvals bind to exact plan version and plan hash.
- Hostname confirmation is required for patch approval and reboot approval.
- Reboot approval is separate from patch approval.
- Host reboot policy can block execution.
- Plan changes invalidate approvals.
- Execution creates durable jobs and records audit events.
- Executor validation happens immediately before work.
- Logs and provider inputs are redacted.

## Runtime Modes

### Development Defaults

```text
COLLECTOR_MODE=demo
EXECUTION_MODE=simulate
DATABASE_URL unset, SQLite development database used
REDIS_URL optional
ADMIN_PASSWORD defaults to admin
```

### Alpha Requirements

```text
APP_ENVIRONMENT=alpha
DATABASE_URL=postgresql or postgresql+psycopg URL
REDIS_URL=redis or rediss URL
ADMIN_PASSWORD or ADMIN_PASSWORD_FILE required
ENCRYPTION_KEY or ENCRYPTION_KEY_FILE required
```

## Source Map

```text
apps/api/sysadmin_api/main.py          HTTP routes
apps/api/sysadmin_api/service.py       Domain workflow
apps/api/sysadmin_api/repository.py    Persistence interface and stores
apps/api/sysadmin_api/runtime.py       Runtime wiring
apps/api/sysadmin_api/security.py      Login, sessions, throttling
apps/api/sysadmin_api/authorization.py Authorization policy
apps/api/sysadmin_api/credentials.py   SSH key vault
apps/api/sysadmin_api/collector.py     Demo and SSH collection
apps/api/sysadmin_api/executor.py      Simulated and Ansible execution
apps/api/sysadmin_api/agents.py        Multi-agent analysis workflow
apps/api/sysadmin_api/providers.py     Model provider routing
apps/api/sysadmin_api/tasks.py         Celery tasks
apps/web/src/App.tsx                   Operator dashboard
apps/web/src/api.ts                    Frontend API client
packages/shared/src/index.ts           Shared TypeScript schemas
ops/ansible/playbooks                  Remediation playbook catalog
agents                                 Versioned agent contracts
docs                                  Supporting contracts and threat model
```

## Related Documents

- `README.md`: setup, modes, and development commands.
- `docs/threat-model.md`: security goals, assumptions, and threats.
- `docs/frontend-campaign-contract.md`: required campaign UI behavior.
- `docs/real-host-integration.md`: guidance for real host testing.
