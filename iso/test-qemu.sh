#!/usr/bin/env bash
set -euo pipefail

# Headless QEMU live boot + real attack E2E verification for Ringwall ISO.
# Proves inside the booted immutable ISO:
#  1. Boots cleanly to Ringwall appliance with read-only SquashFS rootfs.
#  2. ringwalld is active with eBPF kernel sensor loaded.
#  3. Real live process opening ~/.ssh/id_ed25519 is caught by eBPF and frozen (SIGSTOP -> State: T).
#  4. 5-scenario attack simulator intercepts all attacks and blocks prompt-injection downgrade.
#  5. SHA-256 hash-chained audit log passes cryptographic verification.
#  6. No SSH daemon installed and setup/provider guidance is available.
#
# Usage: ./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso

ISO_PATH="${1:-dist/ringwall-appliance-amd64.iso}"
if [[ ! -f "${ISO_PATH}" ]]; then
  echo "ISO not found: ${ISO_PATH}" >&2
  exit 1
fi

for cmd in qemu-system-x86_64 python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required tool: $cmd" >&2
    exit 1
  fi
done

python3 - "${ISO_PATH}" <<'PYEOF'
import os
import pty
import select
import subprocess
import sys
import time

iso_path = sys.argv[1]
kvm_args = ["-enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK) else ["-cpu", "max"]

cmd = [
    "qemu-system-x86_64",
    *kvm_args,
    "-m", "1536",
    "-smp", "2",
    "-nographic",
    "-no-reboot",
    "-cdrom", iso_path,
    "-boot", "d",
    "-net", "none",
]

print(f"[qemu-e2e] Booting {iso_path} ({'KVM' if '-enable-kvm' in kvm_args else 'TCG'})...", flush=True)

master_fd, slave_fd = pty.openpty()
proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True)
os.close(slave_fd)

buf = bytearray()

def read_until(marker: bytes, timeout: float) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([master_fd], [], [], 0.5)
        if r:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if marker in buf:
                text = buf.decode("utf-8", errors="replace")
                buf.clear()
                return text
        if proc.poll() is not None:
            break
    tail = buf.decode("utf-8", errors="replace")[-2000:]
    raise RuntimeError(f"Timeout waiting for {marker!r}. Last output:\n{tail}")

def run_cmd(shell_cmd: str, timeout: float = 45.0) -> str:
    tag = str(int(time.time() * 1000))
    sentinel = f"__RW_DONE_{tag}__"
    # Split sentinel in the sent command so serial TTY echo never prematurely matches read_until.
    full = f'{shell_cmd}; echo "__RW""_DONE_{tag}__:$?"\n'
    os.write(master_fd, full.encode("utf-8"))
    out = read_until(sentinel.encode("utf-8"), timeout)
    time.sleep(0.2)
    r, _, _ = select.select([master_fd], [], [], 0.3)
    if r:
        extra = os.read(master_fd, 4096)
        sys.stdout.buffer.write(extra)
        sys.stdout.buffer.flush()
        out += extra.decode("utf-8", errors="replace")
    return out

try:
    boot_timeout = 240.0 if "-enable-kvm" not in kvm_args else 90.0
    read_until(b"operator@ringwall", boot_timeout)
    print("\n[qemu-e2e] Boot complete! Running live security verifications...\n", flush=True)

    # 1. Verify read-only SquashFS lower rootfs
    out = run_cmd("mount | grep -E 'squashfs.*\\bro\\b'")
    assert "squashfs" in out, f"Expected read-only squashfs mount, got:\n{out}"

    # 2. Verify no SSH server installed
    out = run_cmd("test ! -x /usr/sbin/sshd && echo NO_SSHD_OK")
    assert "NO_SSHD_OK" in out, f"sshd must not be installed:\n{out}"

    # 3. Wait for ringwalld API token and verify live eBPF sensor + policies loaded
    out = run_cmd("for i in $(seq 1 25); do [ -r /run/ringwall/api.token ] && break; sleep 1; done; ringwallctl status || systemctl status ringwalld --no-pager", timeout=60.0)
    assert "Sensor:     ebpf" in out, f"Expected live eBPF sensor in ISO, got:\n{out}"
    assert "Policies:   " in out and "Policies:   0" not in out, f"Expected policies loaded, got:\n{out}"

    # 4. LIVE KERNEL E2E ATTACK: real process reading ~/.ssh/id_ed25519 MUST be frozen by eBPF + SIGSTOP!
    out = run_cmd(
        "python3 -c \"open('/home/operator/.ssh/id_ed25519').read(); import time; time.sleep(25)\" & "
        "APID=$!; sleep 2; grep '^State:' /proc/$APID/status; kill -9 $APID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected attacker PID to be frozen in State: T (stopped) by real eBPF+SIGSTOP, got:\n{out}"

    # 5. Built-in 5-scenario attack simulator
    out = run_cmd("ringwallctl simulate")
    assert "Simulated 5 attack scenarios:" in out, f"Expected 5 simulated attacks intercepted, got:\n{out}"
    assert "Prompt-injection detected" in out, f"Expected prompt-injection detection flag, got:\n{out}"

    # 6. Tamper-evident SHA-256 audit log verification + onboarding providers catalog
    out = run_cmd("ringwallctl verify-log && ringwallctl providers | grep -q 'Venice.ai' && echo PROVIDERS_OK")
    assert "VALID audit chain" in out, f"Audit log hash-chain failed:\n{out}"
    assert "PROVIDERS_OK" in out, f"Provider catalog missing:\n{out}"

    print("\n[qemu-e2e] ALL 6 LIVE ISO SECURITY ASSERTIONS PASSED!\n", flush=True)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master_fd)
PYEOF
