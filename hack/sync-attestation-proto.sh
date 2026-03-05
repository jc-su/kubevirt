#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KUBEVIRT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_SOURCE_PROTO="${KUBEVIRT_DIR}/../attestation-service/proto/v1/attestation.proto"
SOURCE_PROTO="${ATTESTATION_PROTO_SOURCE:-${DEFAULT_SOURCE_PROTO}}"

TARGET_DIR="${KUBEVIRT_DIR}/pkg/virt-handler/trustd/attestationproto/v1"
TARGET_PROTO="${TARGET_DIR}/attestation.proto"

if [[ ! -f "${SOURCE_PROTO}" ]]; then
    echo "error: canonical attestation proto not found at: ${SOURCE_PROTO}" >&2
    echo "hint: set ATTESTATION_PROTO_SOURCE to the canonical attestation.proto path" >&2
    exit 1
fi

if ! command -v protoc >/dev/null 2>&1; then
    echo "error: protoc not found in PATH" >&2
    exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
    gopath_bin="$(go env GOPATH 2>/dev/null)/bin"
    if [[ -n "${gopath_bin}" && -x "${gopath_bin}/protoc-gen-go" ]]; then
        export PATH="${gopath_bin}:${PATH}"
    fi
fi
if ! command -v protoc-gen-go >/dev/null 2>&1; then
    echo "error: protoc-gen-go not found in PATH" >&2
    echo "hint: go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11" >&2
    exit 1
fi

cp "${SOURCE_PROTO}" "${TARGET_PROTO}"

(
    cd "${KUBEVIRT_DIR}/pkg/virt-handler/trustd/attestationproto"
    protoc -I . --go_out=. --go_opt=paths=source_relative v1/attestation.proto
)

echo "synced attestation proto from ${SOURCE_PROTO}"
