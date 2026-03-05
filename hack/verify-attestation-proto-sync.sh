#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KUBEVIRT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_SOURCE_PROTO="${KUBEVIRT_DIR}/../attestation-service/proto/v1/attestation.proto"
SOURCE_PROTO="${ATTESTATION_PROTO_SOURCE:-${DEFAULT_SOURCE_PROTO}}"

TARGET_DIR="${KUBEVIRT_DIR}/pkg/virt-handler/trustd/attestationproto/v1"
TARGET_PROTO="${TARGET_DIR}/attestation.proto"
TARGET_PB_GO="${TARGET_DIR}/attestation.pb.go"

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

if ! cmp -s "${SOURCE_PROTO}" "${TARGET_PROTO}"; then
    echo "error: vendored attestation.proto is out of sync" >&2
    echo "hint: run ./hack/sync-attestation-proto.sh" >&2
    diff -u "${TARGET_PROTO}" "${SOURCE_PROTO}" | sed -n '1,160p' >&2 || true
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

mkdir -p "${tmp_dir}/v1"
cp "${SOURCE_PROTO}" "${tmp_dir}/v1/attestation.proto"
(
    cd "${tmp_dir}"
    protoc -I . --go_out=. --go_opt=paths=source_relative v1/attestation.proto
)

if ! cmp -s "${tmp_dir}/v1/attestation.pb.go" "${TARGET_PB_GO}"; then
    echo "error: vendored attestation.pb.go is out of sync" >&2
    echo "hint: run ./hack/sync-attestation-proto.sh" >&2
    diff -u "${TARGET_PB_GO}" "${tmp_dir}/v1/attestation.pb.go" | sed -n '1,200p' >&2 || true
    exit 1
fi

echo "attestation proto vendoring is synchronized"
