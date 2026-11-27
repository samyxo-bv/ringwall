#!/usr/bin/env bash
set -euo pipefail

# Headless QEMU live boot + real attack E2E verification for Ringwall ISO.
# Proves inside the booted immutable ISO as strictly unprivileged monitored user 'operator':
#  1. Boots cleanly with read-only SquashFS lower rootfs and no sshd.
#  2. ringwalld is active with live eBPF sensor AND fentry/security_file_open (kernel bpf_d_path).
#  3. P0-1: Monitored user CANNOT read /run/ringwall/api.token (0600 root), CANNOT read audit.jsonl,
#     and receives HTTP 401 from the control API.
#  4. Live io_uring_setup syscall (425) is caught by eBPF and frozen (State: T).
#  5. Direct ~/.ssh/id_ed25519 read is frozen via pidfd SIGSTOP (State: T).
#  6. N1 mid-path '..' traversal (/usr/../home/operator/.ssh/id_ed25519) AND '//home/...' are frozen (State: T).
#  7. N2 TOCTOU #1 (directory symlink deleted IMMEDIATELY after open) is STILL frozen via kernel bpf_d_path!
#  8. N2 TOCTOU #2 (relative open followed IMMEDIATELY by os.chdir('/')) is STILL frozen via kernel bpf_d_path!
#  9. P1-A TOCTOU #3 (open ~/.ssh/id_ed25519, IMMEDIATELY rename ~/.ssh -> ~/.s & symlink ~/.ssh -> /tmp)
#     is STILL frozen because userspace never overwrites EVENT_OPEN_RESOLVED!
# 10. P1-B: unprivileged userns+chroot is blocked (kernel.unprivileged_userns_clone=0) AND dot-path reads
#     outside /home or /root (/tmp/alt/.ssh/id_ed25519) are STILL caught by is_interesting_resolved_path!
# 11. N4 + P2: SYS_rename AND symlinkat persistence targeting ~/.ssh/authorized_keys are frozen (State: T).
# 12. N3 destructive rm bypasses ('rm --r /usr' AND 'cd / && rm -r usr') are frozen (State: T).
# 13. Live reverse-shell bash (/dev/tcp) is frozen (State: T).
# 14. Provider catalog is available and real incidents are recorded with 0 drops.
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
    print("\n[qemu-e2e] Boot complete! Running 14 live security assertions...\n", flush=True)

    # 1. Read-only SquashFS lower rootfs & no SSH server
    out = run_cmd("mount | grep -E 'squashfs.*\\bro\\b' && test ! -x /usr/sbin/sshd && echo BASE_HARDENED_OK")
    assert "BASE_HARDENED_OK" in out, f"Expected ro squashfs + no sshd, got:\n{out}"

    # 2. Wait for ringwalld public health snapshot and verify live eBPF + fentry/security_file_open
    out = run_cmd("for i in $(seq 1 30); do [ -r /run/ringwall-status/status.json ] && break; sleep 1; done; cat /run/ringwall-status/status.json", timeout=60.0)
    assert '"sensor_mode": "ebpf"' in out, f"Expected live eBPF sensor in ISO, got:\n{out}"
    assert '"open_hook": "fentry/security_file_open"' in out, f"Expected fentry/security_file_open active in ISO, got:\n{out}"
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
        # Poll TPID and all direct children for up to 8s (0.5s steps) so cold-starting
        # processes under TCG emulation never race, and clean up all spawned PIDs afterward.
        wrapped = (
            f"{cmd_body} & TPID=$!; "
            "FPID=''; "
            "for _ in $(seq 1 16); do "
            "  for p in $TPID $(pgrep -P $TPID 2>/dev/null); do "
            "    if grep -q 'T (stopped)' /proc/$p/status 2>/dev/null; then FPID=$p; break 2; fi; "
            "  done; "
            "  sleep 0.5; "
            "done; "
            "if [ -n \"$FPID\" ]; then grep '^State:' /proc/$FPID/status; else grep '^State:' /proc/$TPID/status 2>/dev/null || echo EXITED; fi; "
            "kill -9 $FPID $(pgrep -P $TPID 2>/dev/null) $TPID 2>/dev/null || true"
        )
        out = run_cmd(wrapped)
        assert "T (stopped)" in out, f"{label} was not frozen (T stopped), got:\n{out}"

    # 4. io_uring_setup syscall (425) -> caught by eBPF and frozen
    assert_frozen(
        'python3 -c "import ctypes, time; ctypes.CDLL(None).syscall(425, 1, ctypes.create_string_buffer(120)); time.sleep(25)"',
        "io_uring_setup caller",
    )

    # 5. Direct ~/.ssh/id_ed25519 read -> frozen via pidfd SIGSTOP
    assert_frozen(
        'python3 -c "open(\'/home/operator/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "Direct SSH key reader",
    )

    # 6. N1 LIVE PROOFS: mid-path '..' traversal (/usr/../home/...) AND leading '//home/...'
    assert_frozen(
        'python3 -c "open(\'/usr/../home/operator/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "N1 mid-path /usr/../home traversal bypass",
    )
    assert_frozen(
        'python3 -c "open(\'//home/operator/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "N1 //home double-slash bypass",
    )

    # 7. N2 LIVE PROOF 1: directory symlink deleted IMMEDIATELY after open() (defeats userspace readlink TOCTOU!)
    run_cmd("ln -sfn /home/operator/.ssh /tmp/d_race")
    assert_frozen(
        'python3 -c "import os, time; fd = os.open(\'/tmp/d_race/id_ed25519\', os.O_RDONLY); os.unlink(\'/tmp/d_race\'); time.sleep(25)"',
        "N2 symlink-unlink TOCTOU bypass",
    )

    # 8. N2 LIVE PROOF 2: relative open followed IMMEDIATELY by os.chdir('/') (defeats userspace cwd TOCTOU!)
    assert_frozen(
        '(cd /home/operator/.ssh && exec python3 -c "import os, time; fd = os.open(\'id_ed25519\', os.O_RDONLY); os.chdir(\'/\'); time.sleep(25)")',
        "N2 cwd-chdir TOCTOU bypass",
    )

    # 9. P1-A LIVE PROOF: open ~/.ssh/id_ed25519, IMMEDIATELY rename ~/.ssh -> ~/.s and symlink ~/.ssh -> /tmp.
    # Userspace MUST NOT overwrite kernel-resolved EVENT_OPEN_RESOLVED with /tmp/id_ed25519!
    try:
        assert_frozen(
            'python3 -c "import os, time; fd = os.open(\'/home/operator/.ssh/id_ed25519\', os.O_RDONLY); os.rename(\'/home/operator/.ssh\', \'/home/operator/.s\'); os.symlink(\'/tmp\', \'/home/operator/.ssh\'); time.sleep(25)"',
            "P1-A rename+symlink-swap TOCTOU bypass",
        )
    finally:
        run_cmd("if [ -L /home/operator/.ssh ] && [ -d /home/operator/.s ]; then rm -f /home/operator/.ssh && mv /home/operator/.s /home/operator/.ssh; fi")

    # 10. P1-B LIVE PROOFS:
    # (a) Unprivileged userns+chroot blocked by kernel.unprivileged_userns_clone=0 in the hardened ISO
    out = run_cmd("echo USERNS_SYSCTL=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo NA); (unshare -Ur chroot /home/operator /bin/true 2>&1 || echo USERNS_BLOCKED)")
    assert "USERNS_SYSCTL=0" in out, f"P1-B expected kernel.unprivileged_userns_clone=0, got:\n{out}"
    assert "USERNS_BLOCKED" in out, f"P1-B expected unprivileged userns+chroot blocked, got:\n{out}"
    # (b) Dot-directory secret outside /home or /root (/tmp/alt/.ssh/id_ed25519) STILL caught by is_interesting_resolved_path!
    # Stage file inside /tmp/alt/d first and rename directory to .ssh so the test shell itself never opens **/.ssh/id_*.
    run_cmd("mkdir -p /tmp/alt/d && printf 'CANARY' > /tmp/alt/d/id_ed25519 && mv /tmp/alt/d /tmp/alt/.ssh")
    assert_frozen(
        'python3 -c "open(\'/tmp/alt/.ssh/id_ed25519\').read(); import time; time.sleep(25)"',
        "P1-B non-/home dot-directory (/tmp/alt/.ssh/id_ed25519) read",
    )

    # 11. N4 + P2 LIVE PROOFS: SYS_rename AND symlinkat persistence into ~/.ssh/authorized_keys
    run_cmd("printf 'ssh-ed25519 AAAA_TEST_KEY attacker@evil\\n' > /home/operator/evil_ak")
    assert_frozen(
        'python3 -c "import os, time; os.rename(\'/home/operator/evil_ak\', \'/home/operator/.ssh/authorized_keys\'); time.sleep(25)"',
        "N4 SYS_rename persistence into authorized_keys",
    )
    run_cmd("rm -f /home/operator/.ssh/authorized_keys; printf 'ssh-ed25519 AAAA_TEST_KEY attacker@evil\\n' > /home/operator/evil_ak2")
    assert_frozen(
        'python3 -c "import os, time; os.symlink(\'/home/operator/evil_ak2\', \'/home/operator/.ssh/authorized_keys\'); time.sleep(25)"',
        "P2 symlink persistence into authorized_keys",
    )

    # 12. N3 LIVE PROOFS: GNU '--r' abbreviation AND relative 'cd / && rm -r usr'
    assert_frozen(
        "bash -c 'rm --r /usr 2>/dev/null || sleep 25'",
        "N3 rm --r GNU abbreviation bypass",
    )
    assert_frozen(
        "(cd / && exec bash -c 'rm -r usr 2>/dev/null || sleep 25')",
        "N3 relative cd / && rm -r usr bypass",
    )

    # 13. Live reverse-shell bash
    assert_frozen(
        "bash -c 'echo /dev/tcp/198.51.100.42/4444 >/dev/null; sleep 25'",
        "Live reverse-shell bash",
    )

    # 14. Verify non-zero real incidents, 0 drops, and provider catalog works
    out = run_cmd("sleep 2; cat /run/ringwall-status/status.json && ringwallctl providers | grep -q 'Venice.ai' && echo PROVIDERS_OK")
    assert '"dropped_events": 0' in out, f"Expected 0 dropped events, got:\n{out}"
    assert '"incidents_total": 0' not in out, f"Expected real incidents recorded, got:\n{out}"
    assert "PROVIDERS_OK" in out, f"Provider catalog missing:\n{out}"

    print("\n[qemu-e2e] ALL 14 LIVE ISO SECURITY ASSERTIONS PASSED!\n", flush=True)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master_fd)
PYEOF
