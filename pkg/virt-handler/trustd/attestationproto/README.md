# Attestation Proto Vendoring

`v1/attestation.proto` and `v1/attestation.pb.go` are vendored from the canonical
source in the sibling `attestation-service` repo:

- canonical source: `../attestation-service/proto/v1/attestation.proto`
- local vendored copy: `pkg/virt-handler/trustd/attestationproto/v1`

Do not edit vendored files by hand. Use:

```bash
./hack/sync-attestation-proto.sh
```

To verify drift:

```bash
./hack/verify-attestation-proto-sync.sh
```
