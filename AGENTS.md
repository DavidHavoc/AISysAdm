# AGENTS.md

This file gives future coding agents the project context needed to work safely
and productively in this repository.

## Required Style

- Never use em dashes in code comments, documentation, commit messages, or user
  facing responses for this project.
- Keep language plain and operational. This is an internal sysadmin control
  plane, not a marketing site.
- Prefer concise, high signal updates and summaries.
- Do not rewrite unrelated files. The worktree may already contain user or
  previous agent changes.

## Project Summary

AI Linux Sysadmin is a private-alpha control plane for inspecting Ubuntu and
Debian hosts, producing evidence-backed findings, and running explicitly
approved patch remediations.

The product combines:

- FastAPI API
- React and Vite operator dashboard
- Shared TypeScript contracts with Zod
- PostgreSQL for durable state
- Redis and Celery for background jobs
- Celery Beat for scheduled tasks
- Fixed SSH collection commands
- Catalog based Ansible execution
- Three agent analysis roles: Linux state analyst, log analyst, and orchestrator

Default local behavior is intentionally safe:

- `COLLECTOR_MODE=demo`
- `EXECUTION_MODE=simulate`

Real host behavior requires explicit SSH and Ansible configuration.

## Repository Map

- `README.md`
  - Product overview, safety model, local setup, integration test instructions,
    and private-alpha limitations.
- `apps/api/sysadmin_api/main.py`
  - FastAPI routes, auth and CSRF dependency wiring, dispatcher selection, and
    API response models.
- `apps/api/sysadmin_api/service.py`
  - Core business logic for hosts, scans, remediations, schedules, campaigns,
    alerts, audit, logs, job processing, leases, retries, and safety gates.
- `apps/api/sysadmin_api/models.py`
  - Pydantic API and domain models. Uses camelCase aliases for JSON.
- `apps/api/sysadmin_api/repository.py`
  - In-memory and SQL repository contracts and persistence implementation.
- `apps/api/sysadmin_api/tasks.py`
  - Celery app, Beat schedule, task dispatch, worker health markers, and retry
    scheduling.
- `apps/api/sysadmin_api/collector.py`
  - Demo and SSH collection behavior.
- `apps/api/sysadmin_api/executor.py`
  - Simulated and Ansible remediation execution.
- `apps/api/sysadmin_api/agents.py`
  - Multi-agent analysis workflow, provider routing, deterministic fallback, and
    remediation plan hashing.
- `apps/api/sysadmin_api/security.py`
  - Auth sessions, CSRF token handling, password validation, and login
    throttling.
- `apps/api/sysadmin_api/authorization.py`
  - Centralized private-alpha authorization policy.
- `apps/api/sysadmin_api/credentials.py`
  - Encrypted SSH private key storage and validation.
- `apps/api/sysadmin_api/redaction.py`
  - Secret redaction for logs, audit details, provider prompts, Celery payloads,
    and exception text.
- `apps/web/src/App.tsx`
  - Main React dashboard. It has historically lagged the backend feature set.
- `apps/web/src/api.ts`
  - Frontend API client. Prefer extending this when adding dashboard workflows.
- `apps/web/src/styles.css`
  - Dashboard styling.
- `packages/shared/src/index.ts`
  - Shared Zod schemas and TypeScript types for frontend contracts.
- `docs/frontend-campaign-contract.md`
  - Required frontend campaign workflow. Read before touching campaign UI.
- `docs/threat-model.md`
  - Private-alpha threat model and accepted risks.
- `ops/ansible/`
  - Fixed playbooks, roles, and callback plugin for remediation execution.
- `agents/`
  - Versioned role contracts for AI agents.
- `scripts/integration.sh`
  - PostgreSQL and Redis integration test stack helper.

## Architecture

High level flow:

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

Scan flow:

1. Operator, schedule, or campaign creates a durable scan job.
2. Celery worker claims the job with a lease.
3. Collector gathers fixed evidence from demo data or SSH.
4. Multi-agent workflow runs Linux state, log analysis, and orchestrator roles.
5. Findings, agent runs, agent messages, logs, and optional remediation plans are
   persisted.
6. Scheduled high or critical findings create alerts.

Remediation flow:

1. A remediation plan is generated from evidence.
2. Operator approves the exact plan version and plan hash.
3. Operator confirms the target hostname.
4. If reboot risk is present, reboot approval is a separate action.
5. Execution job is created only after approval checks pass.
6. Worker revalidates plan binding and host state drift before execution.
7. Simulated executor or catalog based Ansible executor runs the remediation.
8. Logs, result phases, audit events, and campaign status are persisted.

Campaign flow:

1. Create draft campaign with selected host IDs.
2. Queue per-host proposals.
3. Review every host plan separately.
4. Approve patch plan per host with exact hostname confirmation.
5. Approve reboot per host if required.
6. Reject per host when needed.
7. Execute only approved hosts.
8. Cancel queued or scheduled campaign work when needed.

## Safety Invariants

Do not weaken these without explicit user approval and tests:

- AI providers must never invent shell commands that are directly executed.
- Collection and remediation must use predefined catalogs.
- Mutating API routes require authentication and CSRF validation.
- Private-alpha authorization is currently effectively admin-only.
- SSH private keys are encrypted at rest.
- Credential deletion is blocked while hosts reference that credential.
- External provider prompts and persisted operational text must be redacted.
- Remediation approval binds exact `planVersion` and `planHash`.
- Hostname confirmation is required before plan approval.
- Reboot approval is separate from patch plan approval when reboot risk exists.
- Host reboot policy can block remediation when reboot risk cannot be excluded.
- Executor independently validates approval immediately before work.
- Execution must check material host state drift before changing a host.
- Durable jobs use leases, heartbeats, bounded retries, and stale-worker
  recovery.
- Scheduled scans may propose remediations but must not approve or execute them.
- Campaign-wide approval must not exist. Campaign approval is per host only.
- If a campaign host is `plan_changed`, approval must be disabled until a fresh
  proposal is generated.

## Frontend Priorities

The backend API already exposes more workflows than the dashboard shows. The
next logical product work is frontend parity for existing routes.

Start with:

- Credentials
  - List, upload, delete, show fingerprint, show last used timestamp, and handle
    delete conflicts.
- Hosts
  - Create with editable fields, edit, delete, assign credential ID, and show
    connection status.
- Connection testing
  - Call `POST /hosts/{hostId}/test-connection`.
  - If host key confirmation is required, show the fingerprint and require
    explicit confirmation before saving it.
  - Show `sshReachable`, `sudoAvailable`, `osSupported`,
    `ansibleCompatible`, and `checks`.
- Schedules
  - List schedules, edit selected host schedule, show previous and next run.
- Jobs
  - List job type, status, progress, current phase, attempts, last failure, and
    error. Provide a details view.
- Logs
  - List with filters for host, job, scan, remediation, agent run, severity,
    source, phase, and task. Support pagination and details.
- Alerts
  - List and acknowledge.
- Audit
  - List audit events.
- Agent activity
  - List agent runs, filter by scan, show messages for a scan, and surface model
    provider, model, tier, status, latency, tokens, fallback reason, and
    externally processed flag.

Campaign UI must follow `docs/frontend-campaign-contract.md` exactly:

- Create draft with `POST /campaigns`.
- Create proposals with `POST /campaigns/{campaignId}/proposals`.
- Render every `campaign.hosts` item with state, plan version, plan hash, and
  failure summary.
- Approve each host patch plan separately.
- Ask for a second exact hostname confirmation for reboot approval.
- Never offer campaign-wide approval.
- Rejection is per host only.
- Enable execution only when at least one host is approved.
- Use cancel endpoint for queued or scheduled work.
- Disable approval for `plan_changed` and offer proposal regeneration.
- Treat host states as authoritative for mixed outcomes.

## API Notes

Important route groups in `apps/api/sysadmin_api/main.py`:

- Auth
  - `POST /auth/login`
  - `POST /auth/logout`
  - `GET /auth/me`
- Credentials
  - `GET /credentials`
  - `POST /credentials`
  - `DELETE /credentials/{credentialId}`
- Hosts
  - `GET /hosts`
  - `POST /hosts`
  - `PUT /hosts/{hostId}`
  - `DELETE /hosts/{hostId}`
  - `POST /hosts/{hostId}/test-connection`
- Scans and findings
  - `POST /scans`
  - `GET /scans`
  - `GET /scans/{scanId}`
  - `GET /hosts/{hostId}/findings`
  - `GET /findings`
- Remediations
  - `GET /remediations`
  - `POST /remediations/{remediationId}/approve`
  - `POST /remediations/{remediationId}/reboot-approval`
  - `POST /remediations/{remediationId}/execute`
  - `POST /remediations/{remediationId}/reject`
- Jobs and schedules
  - `GET /jobs`
  - `GET /jobs/{jobId}`
  - `GET /hosts/{hostId}/schedule`
  - `PUT /hosts/{hostId}/schedule`
  - `GET /schedules`
- Agent activity
  - `GET /agent-runs`
  - `GET /agent-runs/{scanId}/messages`
- Logs, alerts, and audit
  - `GET /logs`
  - `GET /logs/{logId}`
  - `GET /alerts`
  - `POST /alerts/{alertId}/acknowledge`
  - `GET /audit-events`
- Campaigns
  - `GET /campaigns`
  - `GET /campaigns/{campaignId}`
  - `POST /campaigns`
  - `POST /campaigns/{campaignId}/proposals`
  - `POST /campaigns/{campaignId}/hosts/{hostId}/approve`
  - `POST /campaigns/{campaignId}/hosts/{hostId}/reboot-approval`
  - `POST /campaigns/{campaignId}/hosts/{hostId}/reject`
  - `POST /campaigns/{campaignId}/execute`
  - `POST /campaigns/{campaignId}/cancel`

Frontend JSON uses camelCase because Pydantic models use aliases.

## Local Setup

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e "apps/api[dev]"
npm install
```

Start local infrastructure:

```bash
cp .env.example .env
docker compose up -d postgres redis
```

Required `.env` values:

```text
ADMIN_PASSWORD=<strong password>
ENCRYPTION_KEY=<URL-safe base64 encoding of exactly 32 random bytes>
```

Generate an encryption key:

```bash
python3 -c 'import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Apply migrations:

```bash
.venv/bin/alembic upgrade head
```

Run local services in separate terminals:

```bash
npm run dev:api
.venv/bin/celery -A sysadmin_api.tasks:celery_app worker --loglevel=INFO
.venv/bin/celery -A sysadmin_api.tasks:celery_app beat --loglevel=INFO
npm run dev:web
```

Open:

- Dashboard: `http://localhost:5173`
- API docs: `http://localhost:4000/docs`
- Readiness: `http://localhost:4000/health/ready`

If the dashboard says `Authentication required`, the frontend called a
protected route without a valid `ai_sysadm_session` cookie. Use consistent
hosts such as `localhost` for both web and API, log in again, and check local
cookie settings.

## Common Commands

Run all standard tests:

```bash
npm test
```

Run JavaScript and TypeScript tests:

```bash
npm run test:js
```

Run API tests without integration marker:

```bash
npm run test:api
```

Build all main packages:

```bash
npm run build
```

Build only the web app:

```bash
npm run build --workspace @ai-sysadm/web
```

Run only web tests:

```bash
npm run test --workspace @ai-sysadm/web
```

Run integration suite with isolated PostgreSQL and Redis:

```bash
./scripts/integration.sh test
```

Run integration suite and clean up afterward:

```bash
./scripts/integration.sh verify
```

Clean up integration containers:

```bash
./scripts/integration.sh cleanup
```

## Testing Guidance

For backend changes:

- Add or update focused tests under `apps/api/tests`.
- Use in-memory repository tests for fast behavior checks.
- Use SQLite tests where repository persistence matters but row locking does not.
- Use PostgreSQL integration tests for concurrency, leases, recovery,
  transaction behavior, Alembic migrations, Redis, and Celery behavior.

For frontend changes:

- Update `apps/web/src/App.test.tsx` for major dashboard workflows.
- Mock API behavior through existing test patterns.
- Cover safety-sensitive interactions:
  - login and session handling
  - CSRF-backed mutation paths
  - credential delete conflict display
  - host key confirmation
  - patch approval
  - reboot approval
  - remediation execution
  - campaign proposal generation
  - per-host campaign approval
  - campaign host rejection
  - campaign execution and cancel
  - disabled approval for `plan_changed`

For shared contract changes:

- Update `packages/shared/src/index.ts`.
- Update `packages/shared/src/index.test.ts`.
- Keep schemas aligned with Pydantic models and camelCase JSON aliases.

## Frontend Design Guidance

- Build the actual operator console as the first screen.
- Keep layout dense, scannable, and task focused.
- Use tabs, panels, status chips, tables, filters, and detail drawers or
  sections where appropriate.
- Avoid marketing heroes, decorative backgrounds, and oversized explanatory
  copy.
- Do not put cards inside cards.
- Make destructive actions explicit and confirm them.
- Make safety-sensitive actions require clear typed confirmation where the
  backend expects it.
- Keep button labels short and ensure text does not overflow on mobile or
  desktop.
- Avoid adding dependencies unless there is a clear need.

## Backend Engineering Guidance

- Prefer existing service and repository patterns.
- Keep route handlers thin and put business logic in `SysadminService`.
- Keep persistence logic in repository classes.
- Keep provider or execution boundary code isolated from core policy decisions.
- Preserve redaction on all text that can contain secrets.
- Validate runtime requirements in alpha mode.
- Be careful with timezones and aware datetimes.
- Do not rely on SQLite for row locking behavior.

## Security and Threat Model Notes

Accepted private-alpha risks are documented in `docs/threat-model.md`. Current
known limitations include:

- Single effective admin workflow.
- Localhost alpha may use insecure cookies only for loopback development.
- Redis unavailable fallback for login throttling is per process.
- Credential storage is suitable for private alpha, not a production secret
  manager replacement.
- Live encryption-key rotation is not implemented.
- SQLite is a development convenience only.
- Snapshot and rollback provider integrations are deferred.
- SSH, Ansible, and Ubuntu VM integration coverage is incomplete.
- Deployment packaging, backup and restore automation, and production hardening
  are incomplete.

## When Unsure

1. Read `README.md`, `docs/threat-model.md`, and
   `docs/frontend-campaign-contract.md`.
2. Inspect the API route in `apps/api/sysadmin_api/main.py`.
3. Inspect the service method in `apps/api/sysadmin_api/service.py`.
4. Check shared types in `packages/shared/src/index.ts`.
5. Add the smallest implementation that preserves the safety model.
6. Run the narrowest useful tests, then broader tests if the change touches
   shared behavior.

