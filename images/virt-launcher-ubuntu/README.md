# TDX-compatible `virt-launcher` image

Two-layer image build that lets kubevirt launch Intel TDX VMIs on an
Ubuntu TDX host without recompiling `virt-launcher` from source.

## Problem

kubevirt upstream builds `virt-launcher` on CentOS Stream 10, producing
a Go binary dynamically linked against **el9 userspace conventions**:

- libvirt symbol tags `LIBVIRT_{10.1,10.2,11.2}.0`, `LIBVIRT_ADMIN_11.2.0`
- SONAMEs `libcrypt.so.2`, `libsasl2.so.3`, `libunistring.so.2`, `libpcre.so.1`
- split-daemon binary at `/usr/sbin/virtqemud`
- TDVF at `/usr/share/OVMF/OVMF.inteltdx.fd`

The Ubuntu TDX 2.0 host kernel (`kobuk-team/tdx-release` PPA) is only
KVM-ABI-compatible with **Ubuntu QEMU 9.2.1+tdx2.0 + libvirt 11.0.0+tdx2.0**,
not RHEL QEMU 10.1. Booting a TDX VMI through the stock el9-runtime
launcher dies with `KVM_RUN failed: Input/output error` before the first
vCPU instruction. See the table of ~15 root causes fixed to get here.

## Layers

1. **`Dockerfile`** — Ubuntu 25.04 base + qemu-system-x86 9.2.1+tdx2.0 +
   libvirt 11.0.0+tdx2.0 from the kobuk-team TDX PPA. This is what the
   bazel rules_oci `@tdx_launcher_base` references as the runtime base
   for `virt-launcher-image` — same QEMU/libvirt build the host uses,
   guaranteed KVM-ABI-aligned.

2. **`Dockerfile.launcher-shim`** — layered on top of the bazel-built
   `virt-launcher:devel` image (which contains kubevirt's el9-linked
   Go binaries) and the base image above. This layer:
   - drops in a hex-patched `virt-launcher` binary (libvirt version
     tags rewritten + vna_hash recomputed),
   - drops in a rebuilt `libvirt-admin.so.0.11000.0` with an added
     `LIBVIRT_ADMIN_11.2.0` version script entry + stub
     `virAdmConnectDaemonShutdown`,
   - drops in a rebuilt `/usr/sbin/virtqemud` (Ubuntu builds it but
     drops from the deb via `debian/not-installed`),
   - adds SONAME compat symlinks (libcrypt/libsasl2/libunistring/libpcre),
   - symlinks `/usr/share/OVMF/OVMF.inteltdx.fd` → Ubuntu's merged
     `/usr/share/ovmf/OVMF.fd`.

## Full reproduction sequence

From a fresh checkout on the Ubuntu-TDX host (with the kobuk-team PPA
+ docker + k3s already installed and a local registry running at
`localhost:5000`):

```bash
# 0. Kubelet eviction threshold (one-time; frees scheduling under 10% disk)
sudo cp experiments/platforms/monolithic_tdx/k3s-config.yaml \
        /etc/rancher/k3s/config.yaml
sudo systemctl restart k3s

# 1. Build + push the Ubuntu base (pinned qemu 9.2.1+tdx2.0 + libvirt 11.0+tdx2.0)
cd infra/kubevirt/images/virt-launcher-ubuntu
docker buildx build --provenance=false --sbom=false \
    --output type=image,push=true \
    -t localhost:5000/kubevirt/virt-launcher-base-ubuntu:tdx-plucky .

# Capture the digest and pin it in infra/kubevirt/WORKSPACE's
# tdx_launcher_base oci_pull rule.
docker buildx imagetools inspect \
    localhost:5000/kubevirt/virt-launcher-base-ubuntu:tdx-plucky \
    --format '{{.Manifest.Digest}}'

# 2. Bazel-build the kubevirt launcher against the new base
cd ../../..
DOCKER_PREFIX=localhost:5000/kubevirt DOCKER_TAG=devel \
  PUSH_TARGETS="virt-launcher" \
  make bazel-push-images

# 3. Build + push the shim (patched binary + libvirt-admin + virtqemud
#    wrapper + compat symlinks). This resolves :devel to a digest,
#    pins SOURCE_LAUNCHER_IMAGE to it, then overwrites :devel.
cd images/virt-launcher-ubuntu
./build-launcher-shim.sh

# 4. Bust kubelet's image cache so the next VMI pull gets the new shim
sudo k3s ctr -n k8s.io images rm localhost:5000/kubevirt/virt-launcher:devel

# 5. Smoke-test: launch a minimal monolithic_tdx VMI
kubectl apply --validate=false \
    -f experiments/platforms/monolithic_tdx/vmi-smoketest.yaml

# Expect phase=Running within ~1 min. SSH in via NodePort 31922:
ssh -i experiments/common/ssh-key/id_ed25519 \
    -o StrictHostKeyChecking=no -p 31922 root@127.0.0.1 \
    'cat /dev/null < /dev/tdx_guest && tdx_rtmr 2>&1 | grep ^HASH'
```

## Usage

### 1. Build & push the Ubuntu base

```bash
cd infra/kubevirt/images/virt-launcher-ubuntu
docker buildx build --provenance=false --sbom=false \
    --output type=image,push=true \
    -t localhost:5000/kubevirt/virt-launcher-base-ubuntu:tdx-plucky .

# Record the digest and pin it in infra/kubevirt/WORKSPACE under the
# `tdx_launcher_base` oci_pull rule.
```

### 2. Build the bazel launcher image (pulls the Ubuntu base as runtime)

```bash
cd infra/kubevirt
DOCKER_PREFIX=localhost:5000/kubevirt DOCKER_TAG=devel \
  PUSH_TARGETS="virt-launcher" \
  make bazel-push-images
```

### 3. Run the shim layer on top of that

```bash
cd infra/kubevirt/images/virt-launcher-ubuntu
./build-launcher-shim.sh
```

Final tag (`localhost:5000/kubevirt/virt-launcher:devel`) now carries
everything. Bust the node's containerd cache before redeploying:

```bash
sudo k3s ctr images rm localhost:5000/kubevirt/virt-launcher:devel
```

### 4. Verify

A TDX VMI pod should hit the compute-container log with:

```
starting up libvirt version: 11.0.0-2ubuntu6+tdx2.0~ppa1 (Ubuntu)
qemu version:              9.2.1+ds-1ubuntu4+tdx2.0~ppa2
kernel:                    6.14.0-1009-intel
/usr/bin/qemu-system-x86_64 ... -machine pc-q35-9.2 ...
  -object {"qom-type":"tdx-guest","id":"lsec0","attributes":268435456}
VMI phase: Running
```

and **zero** `kvm run failed: Input/output error` /
`KVM_GET_CLOCK failed: Input/output error` lines.

## Files

- `Dockerfile` — Ubuntu runtime base
- `Dockerfile.launcher-shim` — layer that patches the el9 launcher for Ubuntu
- `build-launcher-shim.sh` — reproducible build of the shim
- `patch-verneed.py` — pyelftools helper that recomputes vna_hash after
  a same-length hex edit of libvirt version strings in the Go binary
- `kobuk-tdx.gpg` — pinned armored GPG key for the TDX PPA

## Caveats

- With lazy binding, the 6 libvirt functions introduced in 10.1/10.2/11.2
  (`virNodeDeviceUpdate`, `virDomainGraphicsReload`,
  `virDomainDelThrottleGroup`, `virDomainSetThrottleGroup`,
  `virDomainGetAutostartOnce`, `virDomainSetAutostartOnce`) will
  **fail at runtime if actually called** — they simply don't exist in
  Ubuntu libvirt 11.0.0. The kubevirt VMI-launch hot path does not call
  them, but a feature that depends on e.g. runtime graphics reload
  would need a real rebuild.
- The `virAdmConnectDaemonShutdown` stub returns `VIR_ERR_NO_SUPPORT`;
  any admin operation that tries to shut down the daemon via RPC will
  error cleanly rather than crash.

## When this stops working

The shim is brittle by design; each new kubevirt release may add
references to newer libvirt APIs or new library deps. If the launcher
pod starts hitting "symbol not found" or "library not found" at load,
re-inspect with `ldd /usr/bin/virt-launcher` and `readelf -V`; pick the
right symlink or rebuild the one affected library from source.

The long-term fix is to host the bazel builder on Ubuntu 25.04 and
drop the shim entirely. That requires building libvirt 11.2+ from
upstream with the kobuk TDX patches rebased (Ubuntu PPA ships 11.0.0
only), which is a separate, larger project.
