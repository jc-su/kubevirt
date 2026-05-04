#!/usr/bin/env bash
#
# Reproducible build of the TDX-compatible virt-launcher image.
#
# Output: localhost:5000/kubevirt/virt-launcher:devel layered on top of:
#   - the bazel-built virt-launcher image (el9 runtime, patched here), and
#   - our Ubuntu 25.04 + TDX PPA base (see ./Dockerfile)
#
# Why two layers: the kubevirt bazel builder compiles virt-launcher on
# CentOS Stream 10 against el9 libvirt-dev; the resulting binary refs
# el9 userspace conventions (libcrypt.so.2, LIBVIRT_11.2.0 symbol tags,
# /usr/sbin/virtqemud split-daemon, /usr/share/OVMF/OVMF.inteltdx.fd).
# Ubuntu 25.04's userspace diverges at every one of those points.
# Rather than re-host the bazel builder on Ubuntu (which would also
# require building libvirt 11.2+ from source to match kubevirt's ABI
# expectations), we shim the el9-built binary to work on Ubuntu:
#   1. Rewrite the binary's .dynstr/verneed version tags from
#      LIBVIRT_{10.1,10.2,11.2}.0  →  LIBVIRT_1.2.{14,15,16}
#      and recompute the corresponding vna_hash fields so glibc's ld.so
#      verneed check accepts Ubuntu libvirt 11.0.0's symbol set.
#   2. Build libvirt-admin.so.0.11000.0 from Ubuntu TDX PPA source with
#      an added LIBVIRT_ADMIN_11.2.0 version-script entry + a stub
#      virAdmConnectDaemonShutdown so the one remaining admin-side
#      version tag the binary refs is satisfied.
#   3. Build virtqemud from the same libvirt source (Ubuntu's deb drops
#      it via debian/not-installed despite meson building it).
#   4. Symlink SONAMEs Ubuntu names differently (libcrypt.so.1 →
#      libcrypt.so.2, libsasl2.so.2 → .so.3, libunistring.so.5 →
#      .so.2, libpcre.so.3 → libpcre.so.1).
#   5. Symlink /usr/share/OVMF/OVMF.inteltdx.fd → Ubuntu's
#      /usr/share/ovmf/OVMF.fd (which ships merged TDVF content).
#
# With lazy binding, the 6 functions introduced in libvirt 10.1/10.2/11.2
# never resolve (they don't exist in 11.0.0) — but they're also not on
# the VMI-launch hot path, so the launcher starts and runs fine.
#
# Prerequisites:
#   - Local docker registry at localhost:5000 with the Ubuntu TDX base
#     already pushed (see ../virt-launcher-base-ubuntu build in Dockerfile
#     sibling) and the bazel-produced launcher already pushed as
#     localhost:5000/kubevirt/virt-launcher:devel.
#   - Host apt sources include Ubuntu plucky + the kobuk-team TDX PPA,
#     so `apt-get source libvirt` pulls the TDX-patched 11.0.0 source.
#   - pyelftools, python3, docker, meson, ninja-build, gcc, pkg-config,
#     libglib2.0-dev, libxml2-dev, libgnutls28-dev.
set -euxo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK=${WORK:-/tmp/vl-shim-build}
mkdir -p "$WORK"

REGISTRY=${REGISTRY:-localhost:5000}
LAUNCHER_IMAGE=${LAUNCHER_IMAGE:-${REGISTRY}/kubevirt/virt-launcher:devel}

# Bazel-built launcher to layer on top of. The :devel tag is pushed
# AND overwritten by this script's final `docker buildx build`, so we
# resolve :devel to an immutable @sha256:... digest first and pin the
# shim's FROM to that digest. Without the pin the `COPY --from=el9base`
# steps would cherry-pick files from a previous shim (self-reference).
if [[ -z "${SOURCE_LAUNCHER_IMAGE:-}" ]]; then
    SOURCE_LAUNCHER_DIGEST=$(docker buildx imagetools inspect \
        "${LAUNCHER_IMAGE}" --format '{{.Manifest.Digest}}' 2>/dev/null ||
        curl -sI "http://${REGISTRY}/v2/kubevirt/virt-launcher/manifests/devel" |
        awk -F': ' '/Docker-Content-Digest/{print $2}' | tr -d '\r\n')
    if [[ -z "$SOURCE_LAUNCHER_DIGEST" ]]; then
        echo "FATAL: cannot resolve ${LAUNCHER_IMAGE} to a digest; run bazel-push-images first" >&2
        exit 1
    fi
    SOURCE_LAUNCHER_IMAGE="${REGISTRY}/kubevirt/virt-launcher@${SOURCE_LAUNCHER_DIGEST}"
fi
echo "[shim] source launcher: ${SOURCE_LAUNCHER_IMAGE}"

# Step 1 — pull the el9-linked virt-launcher binary from the bazel image.
CID=$(docker create "$SOURCE_LAUNCHER_IMAGE")
docker cp "$CID:/usr/bin/virt-launcher" "$WORK/virt-launcher"
docker rm "$CID" >/dev/null
chmod +w "$WORK/virt-launcher"

# Step 2 — hex-swap 14-char libvirt version strings in .dynstr so
# Ubuntu libvirt 11.0.0's set satisfies the launcher's verneed.
python3 - "$WORK/virt-launcher" <<'PY'
import sys
p = sys.argv[1]
mapping = {
    b"LIBVIRT_10.1.0\x00": b"LIBVIRT_1.2.14\x00",
    b"LIBVIRT_10.2.0\x00": b"LIBVIRT_1.2.15\x00",
    b"LIBVIRT_11.2.0\x00": b"LIBVIRT_1.2.16\x00",
}
with open(p, "r+b") as f:
    data = f.read()
    for old, new in mapping.items():
        data = data.replace(old, new)
    f.seek(0); f.write(data); f.truncate()
print("version strings rewritten")
PY

# Step 3 — recompute vna_hash so glibc's verneed matches.
python3 "$SCRIPT_DIR/patch-verneed.py" "$WORK/virt-launcher"

# Step 4 — fetch + patch + build Ubuntu libvirt 11.0.0 (TDX PPA).
LV_SRC=$WORK/libvirt-src
mkdir -p "$LV_SRC"
if [[ ! -d "$LV_SRC/libvirt-11.0.0" ]]; then
    (cd "$LV_SRC" && apt-get source libvirt)
fi

LV=$LV_SRC/libvirt-11.0.0

# 4a. Add stub virAdmConnectDaemonShutdown if not already.
# Appended at EOF rather than spliced mid-file: a prior regex-anchored splice
# landed the stub inside another function's body (the `{[^}]*}` anchor
# matched the first inner brace-pair, not the outer function boundary),
# which left the surrounding function open-ended and the compiler reported
# "static declaration follows non-static declaration" on the block-scoped
# prototype. EOF append is unambiguous.
if ! grep -q "virAdmConnectDaemonShutdown" "$LV/src/admin/libvirt-admin.c"; then
    cat >>"$LV/src/admin/libvirt-admin.c" <<'STUB'


/*
 * Back-ported stub for kubevirt compatibility. virAdmConnectDaemonShutdown
 * was added in libvirt 11.2; we only need the versioned symbol to exist so
 * el9-built binaries resolve at load time. Calls are not expected on this
 * deployment; return -1 if invoked.
 */
int
virAdmConnectDaemonShutdown(virAdmConnectPtr conn G_GNUC_UNUSED,
                            unsigned int flags G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   "virAdmConnectDaemonShutdown unavailable on libvirt 11.0 stub");
    return -1;
}
STUB
    echo "added stub virAdmConnectDaemonShutdown"
fi

# 4b. Add LIBVIRT_ADMIN_11.2.0 version script entry if not already.
if ! grep -q "LIBVIRT_ADMIN_11.2.0" "$LV/src/admin/libvirt_admin_public.syms"; then
    cat >>"$LV/src/admin/libvirt_admin_public.syms" <<'EOF'

LIBVIRT_ADMIN_11.2.0 {
    global:
        virAdmConnectDaemonShutdown;
} LIBVIRT_ADMIN_8.6.0;
EOF
fi

# 4c. Configure + build libvirt-admin.so + virtqemud only.
BUILD=$LV/build-admin
if [[ ! -f "$BUILD/build.ninja" ]]; then
    meson setup "$BUILD" "$LV" \
        -Ddriver_qemu=enabled \
        -Ddriver_libvirtd=enabled \
        -Ddriver_remote=enabled \
        -Ddriver_network=disabled \
        -Ddriver_interface=disabled \
        -Ddriver_libxl=disabled \
        -Ddriver_lxc=disabled \
        -Ddriver_openvz=disabled \
        -Ddriver_esx=disabled \
        -Ddriver_vmware=disabled \
        -Ddriver_vz=disabled \
        -Ddriver_hyperv=disabled \
        -Dsasl=disabled -Dpolkit=disabled -Dselinux=disabled -Dapparmor=disabled \
        -Ddtrace=disabled -Dnls=disabled -Dtests=disabled -Ddocs=disabled
fi
ninja -C "$BUILD" src/libvirt-admin.so.0.11000.0 src/virtqemud

cp "$BUILD/src/libvirt-admin.so.0.11000.0" "$WORK/"
cp "$BUILD/src/virtqemud" "$WORK/"

# Step 5 — assemble the final image from the Dockerfile shim.
cp "$SCRIPT_DIR/Dockerfile.launcher-shim" "$WORK/Dockerfile"
cp "$SCRIPT_DIR/virtqemud-wrapper.sh" "$WORK/virtqemud-wrapper.sh"
cd "$WORK"
docker buildx build --provenance=false --sbom=false \
    --output type=image,push=true \
    --build-arg SOURCE_LAUNCHER_IMAGE="$SOURCE_LAUNCHER_IMAGE" \
    -t "$LAUNCHER_IMAGE" .

echo "done: $LAUNCHER_IMAGE"
