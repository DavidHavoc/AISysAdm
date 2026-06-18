# AI Linux Sysadmin Platform

An approval-gated Linux operations control plane for Ubuntu and Debian cloud VMs. The backend is Python and FastAPI. The operator dashboard remains React.

The safe default is a complete simulation. Real SSH collection and Ansible execution must be enabled explicitly.

## The three AI roles

### 1. Orchestrator AI

The orchestrator uses the configured capable model. It receives normalized host data and both specialist reports, then:

- chooses all updates, security-only updates, or no patching
- explains operational risk and expected impact
- determines rollout size and canary behavior
- predicts reboot impact and estimated downtime
- creates a catalog-based remediation plan
- waits for human approval before patching or rebooting

The orchestrator cannot create shell commands, bypass approval, increase batch size beyond policy, or suppress a policy-detected reboot risk.

### 2. Linux State AI

The Linux state analyst normally uses an economy model. It reads:

- pending packages and security updates
- kernel and current reboot marker
- failed services
- disk, memory, load, and uptime
- package manager state

It produces evidence-backed findings but cannot execute changes.

### 3. Log Analysis AI

The log analyst normally uses an economy model. It reads:

- journal and service failures
- authentication events
- kernel and boot warnings
- apt history

It produces evidence-backed findings but cannot execute changes.

If no provider is configured, all three roles use deterministic local policy analysis. This keeps development and tests useful without sending data to an external model.

## Patch and reboot workflow

1. SSH collection runs a fixed read-only command catalog.
2. Both specialist agents analyze the same normalized snapshot.
3. The orchestrator selects patch scope and creates a plan.
4. The dashboard explains packages, risk, reboot likelihood, downtime, timing, and rollout.
5. One operator approval covers the declared patch plus a reboot only if the post-patch check requires it.
6. Ansible runs prechecks, the selected update playbook, and a reboot-required check.
7. If required and approved, Ansible reboots and waits for SSH to return.
8. Post-patch validation checks package consistency and failed services.
9. On failure, the campaign stops, records an operator notification, and runs predefined recovery diagnostics.

High-risk, high-criticality, and high-availability hosts are always patched one at a time. Other hosts use a canary followed by bounded batches. Maintenance-window plans become approved but wait until their configured window.

## Provider configuration

OpenAI, Anthropic, and Ollama are supported. Model names are intentionally configuration values because model availability and cost change over time.

```bash
cp .env.example .env
```

Configure a strong model and an economy model for any providers you want to use. Provider routing follows `AI_PROVIDER_ORDER`, unless a specific provider is selected for orchestration or specialist work.

## Local setup

Python 3.9 or newer and Node.js are required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e "apps/api[dev]"
npm install
```

Optional PostgreSQL and Redis:

```bash
docker compose up -d
```

Run the API and dashboard in separate terminals:

```bash
npm run dev:api
npm run dev:web
```

Open `http://localhost:5173`. FastAPI documentation is available at `http://localhost:4000/docs`.

## Safe demo and real execution

Defaults:

```text
COLLECTOR_MODE=demo
EXECUTION_MODE=simulate
```

For real hosts, upload an SSH private key through `POST /credentials/ssh-keys`, assign the returned credential ID to a host, install Ansible on the control plane, then set:

```text
COLLECTOR_MODE=ssh
EXECUTION_MODE=ansible
```

The local uploaded-key vault is for demos only. Use a managed secret store before production.

## Persistence

- PostgreSQL stores hosts, scans, evidence, findings, remediations, campaigns, approvals, and execution results.
- Redis stores short-lived agent context with a TTL. It is never the audit source of truth.
- Without either service, the API uses in-memory implementations.

## Snapshot and rollback

Snapshot support remains deferred. Every remediation includes a `preChangeProtection` hook so a future provider-specific or Terraform workflow can run before patching.

## Verification

```bash
npm run build
npm test
```
