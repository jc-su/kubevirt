#!/bin/sh
# virtqemud wrapper. The el9-built kubevirt node-labeller + virt-launcher
# expect split-daemon (virtqemud) + its socket /var/run/libvirt/virtqemud-sock,
# but Ubuntu's libvirt-daemon-system ships monolithic `libvirtd` which
# creates `/var/run/libvirt/libvirt-sock`. Rather than maintain a
# fully-separate virtqemud build (paths, confs, socket routing, etc.),
# invoke the Ubuntu libvirtd in its place: it serves the qemu driver
# just fine, and virsh's default URI probe finds libvirt-sock natively.
#
# We also make virtqemud-sock a symlink to libvirt-sock so anything that
# hardcodes the split-daemon socket path still resolves.
install -d -m 0755 /var/run/libvirt
install -d /etc/libvirt
# Disable libvirtd's TCP listener (needs TLS certs we don't have). Only
# the Unix socket is used by kubevirt.
cat > /etc/libvirt/libvirtd.conf <<'EOF'
listen_tls = 0
listen_tcp = 0
auth_unix_rw = "none"
auth_unix_ro = "none"
unix_sock_rw_perms = "0777"
log_outputs = "1:stderr"
EOF

# Two callers expect different behaviour:
#   - node-labeller.sh (init container): `virtqemud -d` — daemonize + exit
#   - virt-launcher compute: `virtqemud -f /…/virtqemud.conf` — FOREGROUND
#     (it tails the process; exit => crash-loop).
# Branch on whether `-d` / `--daemon` appears in argv.
daemon=0
for a in "$@"; do
    case "$a" in
        -d|--daemon) daemon=1 ;;
    esac
done

if [ "$daemon" = 1 ]; then
    # Background libvirtd (session-detached) and return — matches the
    # contract node-labeller.sh expects from `virtqemud -d`.
    setsid /usr/sbin/libvirtd --listen </dev/null >/var/log/libvirtd.log 2>&1 &
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ -S /var/run/libvirt/libvirt-sock ] && break
        sleep 0.3
    done
    ln -sf libvirt-sock /var/run/libvirt/virtqemud-sock 2>/dev/null || true
    exit 0
fi

# Foreground: kubevirt's libvirt_helper wants the daemon to stay alive
# as a child process so it can monitor it. Pre-create the virtqemud-sock
# → libvirt-sock symlink in the background so kubevirt's client finds
# it as soon as libvirtd binds, then exec libvirtd in the foreground.
# The -f argument passed to us is kubevirt's virtqemud.conf, which is
# layout-compatible with libvirtd.conf for the handful of keys kubevirt
# sets (listen_*, log_*, unix_sock_*).
(
    for i in $(seq 1 60); do
        if [ -S /var/run/libvirt/libvirt-sock ]; then
            ln -sf libvirt-sock /var/run/libvirt/virtqemud-sock 2>/dev/null || true
            exit 0
        fi
        sleep 0.2
    done
) &

exec /usr/sbin/libvirtd --listen "$@"
