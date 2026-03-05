#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KUBEVIRT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_SOURCE_PROTO="${KUBEVIRT_DIR}/../trustd/proto/v1/trustd.proto"
SOURCE_PROTO="${TRUSTD_PROTO_SOURCE:-${DEFAULT_SOURCE_PROTO}}"

TARGET_DIR="${KUBEVIRT_DIR}/pkg/virt-handler/trustd/proto/v1"
TARGET_PROTO="${TARGET_DIR}/trustd.proto"
TARGET_PB_GO="${TARGET_DIR}/trustd.pb.go"
TARGET_GO_PACKAGE='option go_package = "kubevirt.io/kubevirt/pkg/virt-handler/trustd/proto/v1;trustdv1";'

if [[ ! -f "${SOURCE_PROTO}" ]]; then
    echo "error: canonical trustd proto not found at: ${SOURCE_PROTO}" >&2
    echo "hint: set TRUSTD_PROTO_SOURCE to the canonical trustd.proto path" >&2
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

tmp_proto="$(mktemp)"
tmp_dir=""
trap 'rm -f "${tmp_proto}"; if [[ -n "${tmp_dir}" ]]; then rm -rf "${tmp_dir}"; fi' EXIT

cp "${SOURCE_PROTO}" "${tmp_proto}"
sed -E -i "s|^option go_package = \".*\";|${TARGET_GO_PACKAGE}|" "${tmp_proto}"

if ! cmp -s "${tmp_proto}" "${TARGET_PROTO}"; then
    echo "error: vendored trustd.proto is out of sync" >&2
    echo "hint: run ./hack/sync-trustd-proto.sh" >&2
    diff -u "${TARGET_PROTO}" "${tmp_proto}" | sed -n '1,200p' >&2 || true
    exit 1
fi

tmp_dir="$(mktemp -d)"

mkdir -p "${tmp_dir}/v1"
cp "${tmp_proto}" "${tmp_dir}/v1/trustd.proto"
(
    cd "${tmp_dir}"
    protoc -I . --go_out=. --go_opt=paths=source_relative v1/trustd.proto
)

if ! cmp -s "${tmp_dir}/v1/trustd.pb.go" "${TARGET_PB_GO}"; then
    echo "error: vendored trustd.pb.go is out of sync" >&2
    echo "hint: run ./hack/sync-trustd-proto.sh" >&2
    diff -u "${TARGET_PB_GO}" "${tmp_dir}/v1/trustd.pb.go" | sed -n '1,220p' >&2 || true
    exit 1
fi

echo "trustd proto vendoring is synchronized"
