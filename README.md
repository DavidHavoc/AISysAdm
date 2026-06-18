# AI Linux Sysadmin Platform

AI-assisted Linux operations platform for Ubuntu and Debian cloud VMs.

## What is included

- Express control plane with REST APIs for hosts, scans, findings, remediations, and jobs
- Multi-agent analysis pipeline with:
  - orchestrator
  - log analysis agent
  - Linux state analysis agent
- SSH-first host collection interface
- Ansible remediation executor with approval gating
- React dashboard for host inventory, findings, approvals, and execution history
- Shared TypeScript schemas and validation

## Monorepo layout

- `apps/api` control plane API
- `apps/web` internal operator dashboard
- `packages/shared` shared schemas and types
- `ops/ansible` remediation playbooks

## Quick start

```bash
npm install
npm run build
npm run test
```

Run the API:

```bash
npm run dev:api
```

Run the dashboard:

```bash
npm run dev:web
```

## Environment

The API supports optional AI provider configuration for future prompt-based analysis:

- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`
- `OPENAI_MODEL`

If no provider is configured, the analysis agents use deterministic local heuristics.

## Snapshot and rollback

Snapshot orchestration is intentionally deferred in v1. The backend reserves a `preChangeProtection` hook in the remediation pipeline for a future Terraform or provider-native implementation.
