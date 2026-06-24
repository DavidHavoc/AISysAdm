# Threat Model

This document describes the private-alpha security model for AI Linux Sysadmin.
It covers what the control plane protects today, where trust boundaries sit,
which threats are actively mitigated, and which alpha risks are still accepted.

## Assets

- Operator session cookies and CSRF tokens
- Admin credentials and explicit authorization decisions
- Uploaded SSH private keys encrypted at rest
- Host inventory data, fingerprints, schedules, findings, logs, and audits
- Remediation plans, approvals, execution history, and campaign state
- AI provider prompts and responses
- Celery job metadata and failure payloads

## Trust boundaries

- Browser to API: authenticated HTTPS or loopback HTTP during local alpha work
- API to PostgreSQL: durable control-plane state
- API and workers to Redis and Celery: job dispatch, retries, and health markers
- API and workers to AI providers: redacted prompts only
- API and workers to managed hosts: SSH collection and Ansible execution
- Ansible callback plugin to API storage: structured execution events

## Primary threats

- Session theft, stale sessions, or CSRF replay
- Secret leakage through logs, audits, provider prompts, Celery payloads, or
  exception text
- Unauthorized control-plane actions
- Destructive remediation after plan drift or host drift
- Credential deletion that breaks attached hosts
- Cookie downgrade in alpha deployments

## Mitigations

- Authentication uses password hashing, random session tokens, and random CSRF
  tokens.
- Session expiry is enforced with normalized datetimes, and expired sessions are
  deleted when encountered.
- Login attempts are rate-limited per client and username via Redis when
  available, with an in-process fallback counter if Redis is unavailable.
- Mutating routes require both authentication and CSRF validation.
- Protected routes pass through one centralized authorization policy.
- The alpha workflow is intentionally admin-only even though future roles are
  named explicitly as `admin`, `operator`, and `auditor`.
- SSH private keys are encrypted at rest and decrypted only when an SSH or
  Ansible execution boundary needs a short-lived temp file.
- Credential deletion is blocked while any host still references that
  credential.
- Structured Ansible events, fallback process events, audit details, provider
  prompts, Celery payloads, and persisted exception text all go through shared
  secret redaction.
- External AI providers receive redacted prompts only.
- Remediation execution is bound to an approved plan version and hash, requires
  hostname confirmation, and re-checks state drift before making changes.
- Alpha mode requires secure cookies unless the API base URL is loopback and
  the explicit localhost exception is enabled.

## Accepted alpha risks

- Only one effective admin workflow is supported. Multi-user administration and
  delegated roles are not implemented yet.
- Localhost alpha and integration environments may run with insecure cookies to
  avoid breaking loopback development. This is not acceptable for remote
  environments.
- If Redis is unavailable, login throttling falls back to per-process memory,
  which preserves rate limiting but loses cross-process coordination until
  Redis recovers.
- The encrypted credential store is suitable for private alpha evaluation, not
  as a replacement for a dedicated production secrets platform.
- Live encryption-key rotation is not implemented. Rotation requires a planned
  maintenance workflow and credential re-encryption.
- SQLite remains a development convenience and does not replicate PostgreSQL
  locking or timestamp behavior perfectly.
