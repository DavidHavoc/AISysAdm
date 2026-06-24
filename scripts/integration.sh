#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-${ROOT_DIR}/.venv/bin/python}"
COMPOSE_PROJECT="aisysadm-integration"
COMPOSE_FILE="${ROOT_DIR}/compose.integration.yaml"

export APP_ENVIRONMENT="alpha"
export DATABASE_URL="postgresql+psycopg://sysadmin@127.0.0.1:55432/sysadmin_integration"
export REDIS_URL="redis://127.0.0.1:56379/15"
export INTEGRATION_DATABASE_URL="${DATABASE_URL}"
export INTEGRATION_REDIS_URL="${REDIS_URL}"
export ADMIN_USERNAME="integration-admin"
export ADMIN_PASSWORD="integration-test-password"
export ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
export COLLECTOR_MODE="demo"
export EXECUTION_MODE="simulate"
export PYTHONPATH="${ROOT_DIR}/apps/api${PYTHONPATH:+:${PYTHONPATH}}"

compose() {
  docker compose \
    --project-name "${COMPOSE_PROJECT}" \
    --file "${COMPOSE_FILE}" \
    "$@"
}

require_tools() {
  if [[ ! -x "${PYTHON}" ]]; then
    echo "Python environment not found at ${PYTHON}" >&2
    echo "Create .venv and install apps/api[dev] before running integration tests." >&2
    exit 1
  fi
  docker info >/dev/null
}

cleanup_stack() {
  compose down --volumes --remove-orphans
}

start_stack() {
  require_tools
  cleanup_stack
  compose up --detach --wait --wait-timeout 60
  (
    cd "${ROOT_DIR}"
    "${PYTHON}" -m alembic upgrade head
    "${PYTHON}" -m alembic current
  )
}

test_stack() {
  start_stack
  (
    cd "${ROOT_DIR}"
    "${PYTHON}" -m pytest \
      -q \
      -m integration \
      apps/api/tests/integration
  )
}

usage() {
  echo "Usage: $0 {start|test|cleanup|verify}"
}

case "${1:-}" in
  start)
    start_stack
    ;;
  test)
    test_stack
    ;;
  cleanup)
    cleanup_stack
    ;;
  verify)
    trap cleanup_stack EXIT
    test_stack
    ;;
  *)
    usage
    exit 2
    ;;
esac
