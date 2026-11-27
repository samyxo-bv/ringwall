#!/usr/bin/env bash
set -euo pipefail

# Build a hardened, immutable bootable Linux appliance ISO for Ringwall.
# Base: Debian 12 (Bookworm) live-boot + read-only SquashFS + ephemeral RAM overlay.
# Pass DEBIAN_MIRROR (e.g. a snapshot.debian.org URL) and SOURCE_DATE_EPOCH for pinned builds.
#
# Usage:
#   sudo ./iso/build-iso.sh [--out dist/ringwall-appliance-amd64.iso] [--with-model /path/to/model.gguf]

if [[ "${EUID}" -ne 0 ]]; then
  echo "build-iso.sh must be run as root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_ISO="${ROOT_DIR}/dist/ringwall-appliance-amd64.iso"
MODEL_PATH=""
DEBIAN_MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT_ISO="$2"
      shift 2
      ;;
    --with-model)
      MODEL_PATH="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

for cmd in debootstrap mksquashfs grub-mkrescue xorriso; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required host tool: $cmd" >&2
    exit 1
  fi
done

if [[ ! -x "${ROOT_DIR}/bin/ringwalld" || ! -x "${ROOT_DIR}/bin/ringwallctl" ]]; then
  echo "Missing compiled Linux binaries in ${ROOT_DIR}/bin. Run 'make build' first." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/ringwall-iso.XXXXXX)"
CHROOT="${WORK_DIR}/chroot"
ISO_ROOT="${WORK_DIR}/iso"

cleanup() {
  for mp in dev/pts dev proc sys; do
    if mountpoint -q "${CHROOT}/${mp}" 2>/dev/null; then
      umount -lf "${CHROOT}/${mp}" || true
    fi
  done
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

mkdir -p "${CHROOT}" "${ISO_ROOT}/live" "${ISO_ROOT}/boot/grub" "$(dirname "${OUT_ISO}")"

echo "[1/6] Bootstrapping minimal Debian Bookworm rootfs from ${DEBIAN_MIRROR}..."
debootstrap --variant=minbase --arch=amd64 bookworm "${CHROOT}" "${DEBIAN_MIRROR}"

mount --bind /dev "${CHROOT}/dev"
mount --bind /dev/pts "${CHROOT}/dev/pts"
mount -t proc proc "${CHROOT}/proc"
mount -t sysfs sysfs "${CHROOT}/sys"

echo "[2/6] Installing kernel, live-boot, systemd, nftables, and minimal diagnostics..."
cat > "${CHROOT}/etc/apt/sources.list" <<EOF
deb ${DEBIAN_MIRROR} bookworm main
deb ${DEBIAN_MIRROR} bookworm-updates main
deb http://security.debian.org/debian-security bookworm-security main
EOF

chroot "${CHROOT}" /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get update
chroot "${CHROOT}" /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  linux-image-amd64 \
  live-boot \
  systemd-sysv \
  nftables \
  ca-certificates \
  iproute2 \
  procps \
  kmod \
  dbus \
  python3 \
  netcat-openbsd \
  curl

echo "[3/6] Hardening OS image (immutable defaults, no SSH, locked accounts, isolated operator)..."
echo "ringwall" > "${CHROOT}/etc/hostname"
cat > "${CHROOT}/etc/hosts" <<'EOF'
127.0.0.1 localhost ringwall
::1       localhost ip6-localhost ip6-loopback
EOF

# Lock BOTH root and operator passwords (no empty-password PAM login / su bypass).
# Monitored user 'operator' has NO sudo and is NOT in any ringwall admin group;
# /run/ringwall/api.token and /var/log/ringwall/audit.jsonl stay strictly 0600 root:root.
chroot "${CHROOT}" passwd -l root
chroot "${CHROOT}" useradd -m -s /bin/bash -N -g users operator
chroot "${CHROOT}" passwd -l operator

# Pre-seed a harmless canary decoy key (plus a preexisting hardlink outside .ssh)
# so users and QEMU E2E tests prove both path-based and inode-pinned synchronous eBPF LSM blocking.
install -d -m 0700 "${CHROOT}/home/operator/.ssh"
printf 'RINGWALL-CANARY-DECOY-NOT-A-REAL-PRIVATE-KEY\n' > "${CHROOT}/home/operator/.ssh/id_ed25519"
chmod 0600 "${CHROOT}/home/operator/.ssh/id_ed25519"
ln "${CHROOT}/home/operator/.ssh/id_ed25519" "${CHROOT}/home/operator/preexisting_hardlink_canary"
chroot "${CHROOT}" chown -R operator:users /home/operator/.ssh /home/operator/preexisting_hardlink_canary

# Local/serial appliance autologin as strictly unprivileged monitored user (no SSH server installed).
mkdir -p "${CHROOT}/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "${CHROOT}/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin operator --noclear %I 115200,38400,9600 vt102
EOF

mkdir -p "${CHROOT}/etc/systemd/system/getty@tty1.service.d"
cat > "${CHROOT}/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin operator --noclear %I $TERM
EOF

echo "[4/6] Installing Ringwall binaries, eBPF bytecode, policies, firewall, and sysctl hardening..."
install -d -m 0755 "${CHROOT}/usr/local/bin" "${CHROOT}/usr/lib/ringwall" "${CHROOT}/etc/ringwall/policies.d"
install -d -m 0700 "${CHROOT}/etc/ringwall/keys" "${CHROOT}/var/log/ringwall"

install -m 0755 "${ROOT_DIR}/bin/ringwalld" "${CHROOT}/usr/local/bin/ringwalld"
install -m 0755 "${ROOT_DIR}/bin/ringwallctl" "${CHROOT}/usr/local/bin/ringwallctl"
if [[ -f "${ROOT_DIR}/internal/sensor/ringwall.bpf.o" ]]; then
  install -m 0644 "${ROOT_DIR}/internal/sensor/ringwall.bpf.o" "${CHROOT}/usr/lib/ringwall/ringwall.bpf.o"
fi
install -m 0644 "${ROOT_DIR}"/policies/*.yaml "${CHROOT}/etc/ringwall/policies.d/"
# Enable nftables inside the ISO where packaging/nftables.conf is pre-installed.
sed 's/enable_nftables: false/enable_nftables: true/' "${ROOT_DIR}/packaging/ringwall.yaml" > "${CHROOT}/etc/ringwall/ringwall.yaml"
chmod 0600 "${CHROOT}/etc/ringwall/ringwall.yaml"
install -m 0644 "${ROOT_DIR}/packaging/ringwalld.service" "${CHROOT}/etc/systemd/system/ringwalld.service"
install -m 0644 "${ROOT_DIR}/packaging/nftables.conf" "${CHROOT}/etc/nftables.conf"
install -m 0644 "${ROOT_DIR}/packaging/sysctl-99-ringwall.conf" "${CHROOT}/etc/sysctl.d/99-ringwall.conf"

if [[ -n "${MODEL_PATH}" ]]; then
  if [[ ! -f "${MODEL_PATH}" ]]; then
    echo "Model file not found: ${MODEL_PATH}" >&2
    exit 1
  fi
  install -d -m 0755 "${CHROOT}/usr/share/ringwall/models"
  install -m 0644 "${MODEL_PATH}" "${CHROOT}/usr/share/ringwall/models/$(basename "${MODEL_PATH}")"
fi

cat > "${CHROOT}/etc/motd" <<'EOF'
========================================================================
  RINGWALL IMMUTABLE HARDENED APPLIANCE (Read-Only SquashFS + eBPF)
========================================================================
  Root filesystem is read-only SquashFS; reboot wipes all runtime state.
  SSH is not installed. Root & operator passwords are locked.
  Monitored user 'operator' CANNOT read /run/ringwall/api.token (0600 root).

  Read-only health status:  cat /run/ringwall-status/status.json
  Compare AI providers:     ringwallctl providers
========================================================================
EOF

chroot "${CHROOT}" systemctl enable ringwalld.service nftables.service serial-getty@ttyS0.service

chroot "${CHROOT}" apt-get clean
rm -rf "${CHROOT}/var/lib/apt/lists/"* "${CHROOT}/tmp/"* "${CHROOT}/var/tmp/"*

echo "[5/6] Exporting kernel/initrd and packing read-only SquashFS..."
VMLINUZ="$(ls -1 "${CHROOT}"/boot/vmlinuz-* | sort -V | tail -n 1)"
INITRD="$(ls -1 "${CHROOT}"/boot/initrd.img-* | sort -V | tail -n 1)"
cp "${VMLINUZ}" "${ISO_ROOT}/live/vmlinuz"
cp "${INITRD}" "${ISO_ROOT}/live/initrd.img"

for mp in dev/pts dev proc sys; do
  umount -lf "${CHROOT}/${mp}" || true
done

# mksquashfs automatically honors the exported SOURCE_DATE_EPOCH for deterministic timestamps.
mksquashfs "${CHROOT}" "${ISO_ROOT}/live/filesystem.squashfs" \
  -comp xz -b 1M -no-progress -e boot

echo "[6/6] Building hybrid BIOS + UEFI bootable ISO..."
cat > "${ISO_ROOT}/boot/grub/grub.cfg" <<'EOF'
set default=0
set timeout=2

serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input console serial
terminal_output console serial

menuentry "Ringwall Hardened Immutable Appliance (eBPF LSM + Local AI Guardian)" {
    linux /live/vmlinuz boot=live components quiet console=tty0 console=ttyS0,115200n8 lsm=lockdown,yama,integrity,apparmor,bpf ringwall.slot=A lockdown=integrity init_on_alloc=1 init_on_free=1 slab_nomerge pti=on randomize_kstack_offset=on
    initrd /live/initrd.img
}
EOF

grub-mkrescue -o "${OUT_ISO}" "${ISO_ROOT}" -- -volid "RINGWALL_LIVE"
sha256sum "${OUT_ISO}" | tee "${OUT_ISO}.sha256"

echo "Built immutable ISO: ${OUT_ISO} ($(du -h "${OUT_ISO}" | awk '{print $1}'))"
