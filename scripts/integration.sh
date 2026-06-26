#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-${ROOT_DIR}/.venv/bin/python}"
COMPOSE_PROJECT="aisysadm-integration"
COMPOSE_FILE="${ROOT_DIR}/compose.integration.yaml"
REAL_HOST_DIR="${ROOT_DIR}/.data/integration/real-host"
REAL_HOST_KEY_PATH="${REAL_HOST_SSH_KEY:-${REAL_HOST_DIR}/id_ed25519}"
REAL_HOST_UBUNTU_PORT="${REAL_HOST_UBUNTU_PORT:-52222}"

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

compose_real_host() {
  docker compose \
    --project-name "${COMPOSE_PROJECT}" \
    --file "${COMPOSE_FILE}" \
    --profile real-host \
    --profile real-host-debian \
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

require_real_host_tools() {
  require_tools
  for tool in ssh ssh-keygen ssh-keyscan ansible-playbook; do
    if ! command -v "${tool}" >/dev/null; then
      echo "${tool} is required for real-host integration tests." >&2
      exit 1
    fi
  done
}

cleanup_stack() {
  compose_real_host down --volumes --remove-orphans
}

prepare_real_host_key() {
  mkdir -p "${REAL_HOST_DIR}"
  local resolved_key
  resolved_key="$(cd "$(dirname "${REAL_HOST_KEY_PATH}")" && pwd)/$(basename "${REAL_HOST_KEY_PATH}")"
  case "${resolved_key}" in
    "${REAL_HOST_DIR}"/*)
      ;;
    *)
      echo "REAL_HOST_SSH_KEY must be under ${REAL_HOST_DIR}" >&2
      exit 1
      ;;
  esac
  if [[ ! -f "${REAL_HOST_KEY_PATH}" ]]; then
    ssh-keygen -t ed25519 -N "" -f "${REAL_HOST_KEY_PATH}" -C "ai-sysadm-integration" >/dev/null
  fi
  cp "${REAL_HOST_KEY_PATH}.pub" "${REAL_HOST_DIR}/authorized_keys"
  chmod 600 "${REAL_HOST_KEY_PATH}" "${REAL_HOST_DIR}/authorized_keys"
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

wait_for_real_host_ssh() {
  local deadline
  deadline=$((SECONDS + 90))
  until ssh-keyscan -p "${REAL_HOST_UBUNTU_PORT}" -T 2 127.0.0.1 >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "Disposable SSH target did not become reachable on 127.0.0.1:${REAL_HOST_UBUNTU_PORT}" >&2
      exit 1
    fi
    sleep 1
  done
}

start_real_host_stack() {
  require_real_host_tools
  prepare_real_host_key
  cleanup_stack
  REAL_HOST_UBUNTU_PORT="${REAL_HOST_UBUNTU_PORT}" compose_real_host up \
    --detach \
    --wait \
    --wait-timeout 120 \
    postgres \
    redis \
    ubuntu-ssh
  wait_for_real_host_ssh
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
      -m "integration and not real_host and not ansible" \
      apps/api/tests/integration
  )
}

test_real_host_stack() {
  start_real_host_stack
  export REAL_HOST_INTEGRATION="1"
  export REAL_HOST_ADDRESS="127.0.0.1"
  export REAL_HOST_PORT="${REAL_HOST_UBUNTU_PORT}"
  export REAL_HOST_USERNAME="sysadm"
  export REAL_HOST_NAME="ubuntu-ssh"
  export REAL_HOST_SSH_KEY="${REAL_HOST_KEY_PATH}"
  export COLLECTOR_MODE="ssh"
  export EXECUTION_MODE="ansible"
  (
    cd "${ROOT_DIR}"
    "${PYTHON}" -m pytest \
      -q \
      -m "integration and real_host" \
      apps/api/tests/integration
  )
}

usage() {
  echo "Usage: $0 {start|test|real-host|cleanup|verify|verify-real-host}"
}

case "${1:-}" in
  start)
    start_stack
    ;;
  test)
    test_stack
    ;;
  real-host)
    test_real_host_stack
    ;;
  cleanup)
    cleanup_stack
    ;;
  verify)
    trap cleanup_stack EXIT
    test_stack
    ;;
  verify-real-host)
    trap cleanup_stack EXIT
    test_real_host_stack
    ;;
  *)
    usage
    exit 2
    ;;
esac
