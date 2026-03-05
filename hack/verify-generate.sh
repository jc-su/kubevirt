#!/usr/bin/env bash

set -euo pipefail

./hack/verify-attestation-proto-sync.sh
./hack/verify-trustd-proto-sync.sh

if [[ -n $(git status --porcelain 2>/dev/null) ]]; then
    echo "ERROR: git tree state is not clean!"
    echo "You probably need to run 'make generate' or 'make' and commit the changes"
    git status
    git diff
    exit 1
fi
