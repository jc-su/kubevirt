#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export GOCACHE="${GOCACHE:-${ROOT_DIR}/../.cache/go-build}"
mkdir -p "${GOCACHE}"

cd "${ROOT_DIR}"

echo "[tests] trustd collector: untrusted verdict triggers remediation"
go test ./pkg/virt-handler/trustd \
  -run '^TestCollectorRequestsRestartForUntrustedVerdict$' \
  -v

echo "[tests] trustd collector: stale heartbeat miss path"
go test ./pkg/virt-handler/trustd \
  -run '^TestCollectorAppliesStalePolicyOnHeartbeatMiss$' \
  -v

echo "[tests] trustd collector: fail-closed after remediation when re-attest fails"
go test ./pkg/virt-handler/trustd \
  -run '^TestCollectorRemediationLifecycleKeepsFailClosedWhenReattestationFails$' \
  -v

echo "[tests] done"
