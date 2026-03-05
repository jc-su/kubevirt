# trustd Proto Vendoring

`v1/trustd.proto` and `v1/trustd.pb.go` are vendored from the canonical
source in the sibling `trustd` repo:

- canonical source: `../trustd/proto/v1/trustd.proto`
- local vendored copy: `pkg/virt-handler/trustd/proto/v1`

Do not edit vendored files by hand. Use:

```bash
./hack/sync-trustd-proto.sh
```

To verify drift:

```bash
./hack/verify-trustd-proto-sync.sh
```
