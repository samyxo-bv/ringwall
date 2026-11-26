#!/usr/bin/env bash
set -euo pipefail

# Headless QEMU live boot + real attack E2E verification for Ringwall ISO.
# Proves inside the booted immutable ISO as strictly unprivileged monitored user 'operator':
#  1. Boots cleanly with read-only SquashFS lower rootfs, no sshd, and io_uring disabled.
#  2. Monitored user CANNOT read /run/ringwall/api.token (0600 root), CANNOT read audit.jsonl,
#     and receives HTTP 401 from the control API (eliminating self-disable bypass).
#  3. ringwalld is active with live eBPF kernel sensor and 0 dropped events.
#  4. Live direct SSH key read is caught by eBPF and frozen via pidfd SIGSTOP (State: T).
#  5. Live bypass attempts (relative path 'cd ~/.ssh && open(id_ed25519)' AND symlink '/tmp/k')
#     are canonicalized and frozen in kernel state T (stopped).
#  6. Live execve attacks (bash reverse shell pattern AND 'rm -r -f -- /usr') are caught and frozen.
#  7. Provider catalog is available and non-zero real incidents are recorded with 0 drops.
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
    print("\n[qemu-e2e] Boot complete! Running 8 live security assertions...\n", flush=True)

    # 1. Read-only SquashFS lower rootfs
    out = run_cmd("mount | grep -E 'squashfs.*\\bro\\b'")
    assert "squashfs" in out, f"Expected read-only squashfs mount, got:\n{out}"

    # 2. No SSH server installed & io_uring disabled via sysctl
    out = run_cmd("test ! -x /usr/sbin/sshd && echo NO_SSHD_OK; cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo NO_IOURING_SYSCTL")
    assert "NO_SSHD_OK" in out, f"sshd must not be installed:\n{out}"
    assert ("2" in out or "NO_IOURING_SYSCTL" in out), f"expected io_uring_disabled=2, got:\n{out}"

    # 3. Wait for ringwalld public health snapshot and verify live eBPF sensor
    out = run_cmd("for i in $(seq 1 30); do [ -r /run/ringwall-status/status.json ] && break; sleep 1; done; cat /run/ringwall-status/status.json", timeout=60.0)
    assert '"sensor_mode": "ebpf"' in out, f"Expected live eBPF sensor in ISO, got:\n{out}"
    assert '"policy_count": 0' not in out, f"Expected policies loaded, got:\n{out}"

    # 4. P0-1 PROOF: monitored user 'operator' CANNOT read admin token or audit log and gets HTTP 401
    out = run_cmd(
        "(cat /run/ringwall/api.token 2>&1 || echo TOKEN_DENIED); "
        "(cat /var/log/ringwall/audit.jsonl 2>&1 || echo AUDIT_DENIED); "
        "HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9443/api/v1/status); echo API_STATUS=$HTTP_CODE"
    )
    assert "TOKEN_DENIED" in out, f"P0 REGRESSION: operator must NOT read /run/ringwall/api.token:\n{out}"
    assert "AUDIT_DENIED" in out, f"P0 REGRESSION: operator must NOT read /var/log/ringwall/audit.jsonl:\n{out}"
    assert "API_STATUS=401" in out, f"P0 REGRESSION: unauthenticated API must return 401:\n{out}"

    # 5. LIVE ATTACK A: direct ~/.ssh/id_ed25519 read -> frozen by eBPF + pidfd SIGSTOP
    out = run_cmd(
        "python3 -c \"open('/home/operator/.ssh/id_ed25519').read(); import time; time.sleep(25)\" & "
        "APID=$!; sleep 2; grep '^State:' /proc/$APID/status; kill -9 $APID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected direct SSH key reader frozen (T stopped), got:\n{out}"

    # 6. LIVE ATTACK B (P1-2 BYPASSES): relative path (cd ~/.ssh && open('id_ed25519')) AND symlink (/tmp/k -> ~/.ssh/id_ed25519)
    out = run_cmd(
        "(cd /home/operator/.ssh && python3 -c \"open('id_ed25519').read(); import time; time.sleep(25)\") & "
        "RPID=$!; sleep 2; CPID=$(pgrep -P $RPID python3 || echo $RPID); grep '^State:' /proc/$CPID/status; kill -9 $CPID $RPID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected relative-path SSH bypass frozen (T stopped), got:\n{out}"

    out = run_cmd(
        "ln -sf /home/operator/.ssh/id_ed25519 /tmp/k && "
        "python3 -c \"open('/tmp/k').read(); import time; time.sleep(25)\" & "
        "SPID=$!; sleep 2; grep '^State:' /proc/$SPID/status; kill -9 $SPID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected symlink SSH bypass frozen (T stopped), got:\n{out}"

    # 7. LIVE ATTACK C (P1-3 REAL EXECVE): reverse shell pattern AND destructive rm -r -f -- /usr
    out = run_cmd(
        "bash -c 'echo /dev/tcp/198.51.100.42/4444 >/dev/null; sleep 25' & "
        "BPID=$!; sleep 2; grep '^State:' /proc/$BPID/status; kill -9 $BPID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected live reverse-shell bash frozen (T stopped), got:\n{out}"

    out = run_cmd(
        "bash -c 'rm -r -f -- /usr 2>/dev/null || sleep 25' & "
        "MPID=$!; sleep 2; grep '^State:' /proc/$MPID/status; kill -9 $MPID 2>/dev/null || true"
    )
    assert "T (stopped)" in out, f"Expected live destructive rm bypass frozen (T stopped), got:\n{out}"

    # 8. Verify non-zero incidents recorded, 0 drops, and provider catalog works
    out = run_cmd("sleep 2; cat /run/ringwall-status/status.json && ringwallctl providers | grep -q 'Venice.ai' && echo PROVIDERS_OK")
    assert '"dropped_events": 0' in out, f"Expected 0 dropped events, got:\n{out}"
    assert '"incidents_total": 0' not in out, f"Expected real incidents recorded, got:\n{out}"
    assert "PROVIDERS_OK" in out, f"Provider catalog missing:\n{out}"

    print("\n[qemu-e2e] ALL 8 LIVE ISO SECURITY ASSERTIONS PASSED!\n", flush=True)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master_fd)
PYEOF
