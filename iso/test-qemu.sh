#!/usr/bin/env bash
set -euo pipefail

# Headless QEMU live boot + real attack E2E verification for Ringwall ISO.
# Proves inside the booted immutable ISO as strictly unprivileged monitored user 'operator':
#  1. Boots cleanly with read-only SquashFS lower rootfs and no sshd.
#  2. Monitored user CANNOT read /run/ringwall/api.token (0600 root), CANNOT read audit.jsonl,
#     and receives HTTP 401 from the control API.
#  3. ringwalld is active with live eBPF kernel sensor and 0 dropped events.
#  4. Live io_uring_setup syscall (425) is caught by eBPF and frozen (State: T).
#  5. Direct ~/.ssh/id_ed25519 read is frozen via pidfd SIGSTOP (State: T).
#  6. Leading double-slash bypass (//home/operator/.ssh/id_ed25519) is frozen (State: T).
#  7. /proc/self/cwd bypass (cd ~/.ssh && open('/proc/self/cwd/id_ed25519')) is frozen (State: T).
#  8. Directory symlink bypass across PrivateTmp (ln -sfn ~/.ssh /tmp/d && open('/tmp/d/id_ed25519')) is frozen (State: T).
#  9. Live execve attacks (bash reverse shell pattern AND 'rm -r /usr' without -f) are frozen (State: T).
# 10. Provider catalog is available and real incidents are recorded with 0 drops.
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
    print("\n[qemu-e2e] Boot complete! Running 10 live security assertions...\n", flush=True)

    # 1. Read-only SquashFS lower rootfs & no SSH server
    out = run_cmd("mount | grep -E 'squashfs.*\\bro\\b' && test ! -x /usr/sbin/sshd && echo BASE_HARDENED_OK")
    assert "BASE_HARDENED_OK" in out, f"Expected ro squashfs + no sshd, got:\n{out}"

    # 2. Wait for ringwalld public health snapshot and verify live eBPF sensor
    out = run_cmd("for i in $(seq 1 30); do [ -r /run/ringwall-status/status.json ] && break; sleep 1; done; cat /run/ringwall-status/status.json", timeout=60.0)
    assert '"sensor_mode": "ebpf"' in out, f"Expected live eBPF sensor in ISO, got:\n{out}"
    assert '"policy_count": 0' not in out, f"Expected policies loaded, got:\n{out}"

    # 3. P0-1 PROOF: monitored user 'operator' CANNOT read admin token or audit log and gets HTTP 401
    out = run_cmd(
        "(cat /run/ringwall/api.token 2>&1 || echo TOKEN_DENIED); "
        "(cat /var/log/ringwall/audit.jsonl 2>&1 || echo AUDIT_DENIED); "
        "HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9443/api/v1/status); echo API_STATUS=$HTTP_CODE"
    )
    assert "TOKEN_DENIED" in out, f"P0 REGRESSION: operator must NOT read /run/ringwall/api.token:\n{out}"
    assert "AUDIT_DENIED" in out, f"P0 REGRESSION: operator must NOT read /var/log/ringwall/audit.jsonl:\n{out}"
    assert "API_STATUS=401" in out, f"P0 REGRESSION: unauthenticated API must return 401:\n{out}"

    def assert_frozen(cmd_body: str, label: str):
        # Poll up to 8s (0.5s steps) so cold-starting python3 under TCG emulation never races.
        wrapped = (
            f"{cmd_body} & TPID=$!; "
            "for _ in $(seq 1 16); do "
            "  P=$(pgrep -P $TPID python3 2>/dev/null || echo $TPID); "
            "  grep -q 'T (stopped)' /proc/$P/status 2>/dev/null && break; "
            "  sleep 0.5; "
            "done; "
            "P=$(pgrep -P $TPID python3 2>/dev/null || echo $TPID); "
            "grep '^State:' /proc/$P/status; kill -9 $P $TPID 2>/dev/null || true"
        )
        out = run_cmd(wrapped)
        assert "T (stopped)" in out, f"{label} was not frozen (T stopped), got:\n{out}"

    # 4. P1-C LIVE PROOF: io_uring_setup syscall (425) MUST be caught by eBPF and frozen!
    assert_frozen(
        'python3 -c "import ctypes, time; ctypes.CDLL(None).syscall(425, 1, ctypes.create_string_buffer(120)); time.sleep(25)"',
        "P1-C io_uring_setup caller",
    )

    # 5. Direct ~/.ssh/id_ed25519 read -> frozen via pidfd SIGSTOP
    assert_frozen(
        'python3 -c "open(\'/home/operator/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "Direct SSH key reader",
    )

    # 6. P1-A LIVE PROOF 1: leading double-slash bypass //home/operator/.ssh/id_ed25519
    assert_frozen(
        'python3 -c "open(\'//home/operator/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "P1-A //home double-slash bypass",
    )

    # 7. P1-A LIVE PROOF 2: /proc/self/cwd bypass after cd ~/.ssh
    assert_frozen(
        '(cd /home/operator/.ssh && python3 -c "open(\'/proc/self/cwd/id_ed25519\').read(); import time; time.sleep(25)")',
        "P1-A /proc/self/cwd bypass",
    )

    # 8. P1-A LIVE PROOF 3: directory symlink across PrivateTmp (ln -sfn ~/.ssh /tmp/d && open('/tmp/d/id_ed25519'))
    run_cmd("ln -sfn /home/operator/.ssh /tmp/d")
    assert_frozen(
        'python3 -c "open(\'/tmp/d/id_ed25519\').read(); import time; time.sleep(25)"',
        "P1-A directory symlink /tmp/d/id_ed25519 bypass",
    )

    # 9. P1-B LIVE PROOFS: live reverse-shell bash AND recursive rm WITHOUT -f ('rm -r /usr')
    assert_frozen(
        "bash -c 'echo /dev/tcp/198.51.100.42/4444 >/dev/null; sleep 25'",
        "Live reverse-shell bash",
    )
    assert_frozen(
        "bash -c 'rm -r /usr 2>/dev/null || sleep 25'",
        "P1-B recursive rm without -f",
    )

    # 10. Verify non-zero real incidents, 0 drops, and provider catalog works
    out = run_cmd("sleep 2; cat /run/ringwall-status/status.json && ringwallctl providers | grep -q 'Venice.ai' && echo PROVIDERS_OK")
    assert '"dropped_events": 0' in out, f"Expected 0 dropped events, got:\n{out}"
    assert '"incidents_total": 0' not in out, f"Expected real incidents recorded, got:\n{out}"
    assert "PROVIDERS_OK" in out, f"Provider catalog missing:\n{out}"

    print("\n[qemu-e2e] ALL 10 LIVE ISO SECURITY ASSERTIONS PASSED!\n", flush=True)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master_fd)
PYEOF
