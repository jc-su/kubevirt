# Ubuntu-based virt-launcher runtime base for TDX hosts.
#
# Why: the stock virt-launcher ships el9 RPMs (qemu-kvm 10.1 + libvirt 11.9)
# that are ABI-incompatible with the Ubuntu TDX 2.0 host kernel (KVM_RUN
# returns -EIO before first vCPU instruction). This image replaces the
# launcher's runtime with the same Ubuntu PPA QEMU + libvirt stack that
# start-qemu.sh uses on the host — identical KVM ABI = TD boots.
#
# The kubevirt bazel build lays its own binaries (virt-launcher,
# virt-launcher-monitor, libvirt-hook-client, passwd/nsswitch/qemu.conf,
# /var/run relative symlink) on top of this image via tar layers. Keep
# this image minimal — only the apt-installed runtime, plus the path
# compat symlinks libvirt-on-Ubuntu needs to cooperate with kubevirt.
FROM ubuntu:25.04

ARG DEBIAN_FRONTEND=noninteractive

# Bring in the kobuk-team TDX PPA on plucky. This is where the TDX-patched
# qemu-system-x86 9.2.1+tdx2.0~ppa2 and libvirt 11.0.0-2ubuntu6+tdx2.0~ppa1
# live; the ubuntu/plucky archive ships a non-TDX QEMU.
#
# The PPA key is pinned as an armored .asc so the image builds offline-safe
# from the host's existing /etc/apt trust (same key the host uses).
COPY kobuk-tdx.gpg /etc/apt/trusted.gpg.d/kobuk-tdx.gpg
RUN set -eux; \
    # ubuntu:25.04 base has no CA bundle, so TLS to ppa.launchpadcontent.net
    # fails during `apt update` before any -y install completes. Install
    # ca-certificates from the archive first, then add the PPA source.
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    printf '%s\n' \
      'deb [signed-by=/etc/apt/trusted.gpg.d/kobuk-tdx.gpg] https://ppa.launchpadcontent.net/kobuk-team/tdx-release/ubuntu plucky main' \
      > /etc/apt/sources.list.d/kobuk-tdx.list; \
    # Pin the PPA with priority 1001 so its qemu/libvirt win over the
    # plucky-updates versions. The archive ships qemu 9.2.1+ds-1ubuntu5.2
    # and libvirt 11.0.0-2ubuntu6.5 without the TDX 2.0 patches the host
    # kernel expects; we must use the same +tdx2.0~ppa versions the host
    # runs to keep QEMU's KVM ABI aligned.
    printf '%s\n' \
      'Package: *' \
      'Pin: release o=LP-PPA-kobuk-team-tdx-release' \
      'Pin-Priority: 1001' \
      > /etc/apt/preferences.d/99-kobuk-tdx; \
    apt-get update; \
    # --allow-downgrades: the PPA version strings (e.g. 11.0.0-2ubuntu6+tdx2.0~ppa1)
    # sort LOWER than the archive's security update (11.0.0-2ubuntu6.5) under
    # Debian versioning — the `~` glyph is "pre-release". Without this flag
    # apt refuses to select the PPA build even at pin priority 1001 and
    # silently falls back to the non-TDX archive version.
    apt-get install -y --no-install-recommends --allow-downgrades \
        qemu-system-x86 \
        qemu-utils \
        libvirt-daemon-system \
        libvirt-daemon-driver-qemu \
        libvirt-clients \
        libvirt0 \
        ovmf \
        seabios \
        swtpm \
        swtpm-tools \
        dmidecode \
        iproute2 \
        iptables \
        nftables \
        socat \
        xorriso \
        openssl \
        ca-certificates \
        procps \
        util-linux \
        e2fsprogs \
        xfsprogs \
        dosfstools \
        libcap2-bin \
        python3-minimal; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# libvirt on Ubuntu invokes /usr/bin/qemu-system-x86_64; kubevirt in a few
# places still references the RHEL /usr/libexec/qemu-kvm path. A symlink
# costs nothing and saves a converter patch.
RUN ln -sf /usr/bin/qemu-system-x86_64 /usr/libexec/qemu-kvm

# Kubevirt's virt-handler inspects the launcher pod's FS via /proc/<pid>/root.
# An absolute /var/run -> /run symlink confuses that path (kernel resolves
# the absolute target against virt-handler's root, not the container's root).
# Ubuntu 25.04 ships /var/run as an absolute symlink; rewrite to relative.
# (KubeVirt's bazel build also lays down a relative symlink via
# var-run-symlink-tar — this line is defense in depth for non-bazel image
# consumers.)
RUN rm -f /var/run && ln -s ../run /var/run

# Create the qemu user/group that libvirt drops privileges to. kubevirt's
# passwd-tar also creates these, but having them here means the base image
# works standalone (e.g. for debugging with `docker run`).
RUN groupadd -g 107 qemu 2>/dev/null || true; \
    useradd  -u 107 -g 107 -M -d /home/qemu -s /bin/bash qemu 2>/dev/null || true

# Ensure libvirt socket/state dirs exist with the permissions libvirt expects.
# These are normally created by the libvirt postinst; noop if already present.
RUN install -d -m 0755 -o root -g root /var/lib/libvirt /var/run/libvirt \
    /var/log/libvirt /etc/libvirt/hooks
