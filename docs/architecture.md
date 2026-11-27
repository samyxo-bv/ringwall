# Ringwall by Samyxo — Architecture

Ringwall is designed around a single security rule: **deterministic kernel enforcement executes synchronously first; userspace policies, self-healing, and AI triage sit strictly above it and can never weaken it.**

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Linux Kernel Space (ebpf/ringwall.bpf.c)                                   │
│                                                                            │
│  Tier 1 — Fail-Closed Synchronous eBPF LSM (when lsm=...,bpf is active)    │
│    • lsm/file_open           -> bpf_d_path into per-CPU scratch BEFORE     │
│                                 ringbuf reserve; -EPERM on SSH private     │
│                                 keys & pinned secret inodes (fail-closed   │
│                                 even under ringbuf saturation floods);     │
│                                 revokes opt-in exemption if task->ptrace!=0│
│    • lsm/mmap_file           -> -EPERM if opt-in SSH exe maps non-root or  │
│                                 mode & 0022 PROT_EXEC object (LD_PRELOAD)  │
│    • lsm/ptrace_access_check -> -EPERM for non-root ptrace into opt-in SSH │
│    • lsm/bprm_check_security -> -EPERM pre-exec on virtual-patched inodes  │
│                                 with inode->i_generation check             │
│                                                                            │
│  Tier 2 Fallback (BTF without bpf LSM): fentry/security_file_open          │
│  Tier 3 Fallback (older kernels):       sys_enter_openat / openat2 / creat │
│                                                                            │
│  Always-On Syscall Tracepoints (4 MiB BPF ringbuf + per-CPU drop counter)  │
│    • execve, execveat, rename/at/at2, link/at, symlink/at,                 │
│      connect, sendto, io_uring_setup                                       │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │ 1344-byte RawEvent records
                                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Userspace Daemon (ringwalld — root:root)                                   │
│                                                                            │
│  1. Lineage Tracker (internal/lineage)                                     │
│     • Preserves kernel bpf_d_path verbatim (EVENT_OPEN_RESOLVED/BLOCKED)   │
│     • Parent-only symlink resolve for link/rename destinations             │
│     • Full process ancestry, exe path, Cwd, pid start time                 │
│                                                                            │
│  2. Deterministic Policy Engine (internal/policy) — 0 ms                   │
│     • Static YAML packs (/etc/ringwall/policies.d/*.yaml)                  │
│     • Dynamic TTL-bounded Virtual Rules (/var/lib/ringwall/virtual-        │
│       patches.json), guarded by runtime vpExeGuard (outside RLock)         │
│                                                                            │
│  3. Immediate Enforcer (internal/enforcer)                                 │
│     • pidfd_open + /proc/<pid>/stat starttime-verified SIGSTOP / SIGKILL   │
│     • Root-owned cgroup v2 cgroup.freeze (when isolated in container/unit) │
│     • Agent ancestor freeze (prevents parent agent sending SIGCONT)        │
│     • Direct argv nftables blocked_v4 / blocked_v6 updates (zero shell)    │
│                                                                            │
│  4. Self-Healing Engine (internal/scanner + internal/patcher)              │
│     • dpkg/apk inventory, deleted .so maps, sysctl & 0600 drift            │
│     • OSV.dev + CISA KEV (opt-in) / offline JSON bundle                    │
│     • Security-only apt-get auto-patcher + protected service restarts      │
│     • Virtual Patcher (anti-lockout inode index + O_PATH|O_NOFOLLOW sync)  │
│     • Signed Ed25519 A/B immutable slot updater (disk-installed boot)      │
│                                                                            │
│  5. Bounded Uncensored AI Guardian (internal/guardian) — async / 2nd       │
│     • Secret-redacted telemetry + prompt-injection tagging                 │
│     • Multi-model pool: tiered | consensus (fail-closed) | failover        │
│     • HARD INVARIANT: EnforceInvariant blocks any verdict downgrade        │
│                                                                            │
│  6. Tamper-Evident Audit Log & Root-Only Control Plane (127.0.0.1:9443)    │
│     • SHA-256 hash-chained /var/log/ringwall/audit.jsonl (0600 root)       │
│     • Bearer token in /run/ringwall/api.token (0600 root)                  │
│     • Non-sensitive public snapshot in /run/ringwall-status/status.json    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Three-Tier Kernel Sensor & Automatic Fallback

Ringwall ships a single CO-RE eBPF object (`ebpf/ringwall.bpf.c`, embedded directly inside `ringwalld` via `-tags ebpf_embed`) and selects the strongest available hook tier at startup (`internal/sensor/ebpf_linux.go`):

1. **Tier 1 — Synchronous eBPF LSM (`lsm/file_open`, `lsm/mmap_file`, `lsm/ptrace_access_check`, `lsm/bprm_check_security`):**
   - Activated automatically whenever `/sys/kernel/security/lsm` contains `bpf` (default in the Ringwall ISO).
   - `config_map[0]` holds `ringwalld`'s own PID so the daemon never blocks or loops on itself.
   - `config_map[1]` toggles synchronous enforcement (`1` in `interactive`/`strict` mode when `sensor.enable_lsm_blocking: true`; `0` in `audit` mode).
   - **Fail-closed under floods:** `trace_lsm_file_open` resolves `bpf_d_path` into a per-CPU scratch map (`path_scratch_map`) and decides `should_block` **before** calling `bpf_ringbuf_reserve`. If an attacker floods the 4 MiB ring buffer (for example with UDP `sendto` storms), `record_drop()` increments `stats_map` and the kernel **still returns `-1` (`-EPERM`)** before a single byte is read.
   - **Hardlink & rename resistance:** `lsm_deny_file_inodes` pins `(s_dev, i_ino)` of existing SSH private keys at daemon startup (including both overlayfs lower and upper `s_dev` keys). Hardlinks outside `.ssh` or source-renames of pinned keys still hit `lsm_deny_file_inodes` and receive `-EPERM`.
   - **Caller anti-spoofing & zero-exemption default:** `allowed_ssh_exe_inodes` checks kernel `current->mm->exe_file` `(s_dev, i_ino)` (immune to `PR_SET_NAME` and `/tmp/ssh` copies). It is **empty by default** so `ssh -F` and rogue `SSH_AUTH_SOCK` `ssh-add` cannot exfiltrate keys.
   - **Opt-in binary hardening:** If an operator opts specific SSH binaries into `sensor.lsm_allowed_ssh_exes`, `lsm/mmap_file` synchronously returns `-EPERM` on any non-root-owned or group/world-writable (`mode & 0022`) `PROT_EXEC` mapping (defeating `LD_PRELOAD` across `fork()` and `pthread_create()` before attacker code executes), while `is_allowed_ssh_exe()` revokes the exemption immediately whenever `task->ptrace != 0` (defeating pre-exec `strace` / `PTRACE_TRACEME`).
   - **Virtual-patch execution blocking & inode reuse protection:** `lsm/bprm_check_security` checks `lsm_deny_exec_inodes` using `(s_dev, i_ino)` plus an optional `inode->i_generation` value (`FS_IOC_GETVERSION` on `ext4`/`xfs`/`btrfs`). If a vulnerable binary is upgraded and the filesystem reuses its inode number for a newer system binary, `cur_gen != dv->gen` lets execution proceed immediately.

2. **Tier 2 — Kernel-Resolved Tracing (`fentry/security_file_open`):**
   - Used on BTF-capable kernels without `lsm=...,bpf`.
   - Emits `EVENT_OPEN_RESOLVED` with canonical `bpf_d_path` strings so userspace never overwrites kernel paths with race-prone `readlink` calls. Enforcement is asynchronous (`SIGSTOP` after open).

3. **Tier 3 — Hardened Syscall Tracepoints (`sys_enter_openat*`) & `procfs`:**
   - Used on older non-BTF kernels (`sys_enter_openat`, `openat2`, `open`, `creat`) or containers without `CAP_BPF` (`procfs` poller).

---

## 2. Lineage & Path Canonicalization Rules

`internal/lineage/tracker.go` enforces three strict rules to avoid TOCTOU races:
- **`EVENT_OPEN_RESOLVED` and `EVENT_OPEN_BLOCKED` (`PathResolved == true`):** The path came directly from kernel `bpf_d_path`. Userspace only normalizes slashes and **never** calls `readlink` or overwrites it.
- **`EVENT_LINK_DEST` (`ResolveParentOnly == true`):** Used for `rename*`, `link*`, and `symlink*` destination paths. Resolves symlinks only on parent directories so `symlink(evil, ~/.ssh/authorized_keys)` keeps the leaf `authorized_keys` and reliably triggers `RW-CORE-005`.
- **Fallback raw tracepoints (`EVENT_OPENAT`):** Resolves `dirfd` (`/proc/<pid>/fd/<n>`), `cwd`, `/proc/self/root`, and component-wise symlinks before policy evaluation.

---

## 3. Process-Safe Enforcement (`pidfd` + Cgroup v2 + `nftables`)

`internal/enforcer/` avoids classic PID-reuse races and shell-injection bugs:
- **PID-reuse safety:** `SignalVerified` opens a `pidfd` (`SYS_pidfd_open`), verifies `/proc/<pid>/stat` field 22 (`starttime`) matches the captured event start time, and delivers `SIGSTOP` or `SIGKILL` via `SYS_pidfd_send_signal`.
- **Anti-resume for AI agents:** When an incident matches a process descended from a known coding agent (`claude`, `codex`, `cursor`, `openclaw`, `aider`, `copilot`, `mcp`, `agent`), Ringwall freezes the agent ancestor too so it cannot send `SIGCONT` to its frozen child. If the process runs in a dedicated cgroup v2 unit/container, Ringwall freezes the cgroup via `cgroup.freeze`.
- **Zero-shell firewalling:** `nftables` egress blocking invokes `exec.Command("nft", "add", "element", family, table, setName, ...)` with strict table regex validation (`^[a-zA-Z0-9_]+ [a-zA-Z0-9_]+$`), refusing loopback, private, link-local, unspecified, and zoned IP addresses.

---

## 4. Privilege Separation & File Permissions

| Path | Mode / Owner | Purpose |
|---|---|---|
| `/run/ringwall/api.token` | `0600 root:root` | Auto-generated 256-bit bearer token for `127.0.0.1:9443` |
| `/etc/ringwall/ringwall.yaml` | `0600 root:root` | Daemon configuration |
| `/etc/ringwall/keys/*.key` | `0600 root:root` | Separate AI provider API key files (never stored inline in YAML) |
| `/var/log/ringwall/audit.jsonl` | `0600 root:root` | Tamper-evident SHA-256 hash-chained JSONL audit log |
| `/var/lib/ringwall/virtual-patches.json` | `0600 root:root` | Persisted TTL-bounded virtual patch state (outside `policy_dirs`) |
| `/var/lib/ringwall/ab-state.json` | `0600 root:root` | A/B slot state and boot rollback counter |
| `/run/ringwall-status/status.json` | `0644 root:root` | Non-sensitive health snapshot readable by unprivileged users |

---

## 5. Bounded Uncensored AI Guardian

`internal/guardian/` runs **after** deterministic enforcement:
- **Redaction before send:** Strips common tokens, bearer strings, private key blocks, and high-entropy secret patterns before calling any local or opted-in cloud model.
- **Refusal detection & failover:** Detects common LLM safety refusals (for example `"I cannot assist with malware"`) and automatically fails over or escalates to Tier 2.
- **Multi-model strategies:**
  - `tiered` (default): Fast local Tier 1 model first; Tier 2 runs only when risk ≥ `escalate_threshold`, prompt-injection markers are present, or Tier 1 refuses/errors.
  - `consensus`: Queries all configured models in parallel and merges **fail-closed** (strictest action & highest risk win).
  - `failover`: Tries models in order until one returns valid non-refusal JSON.
- **Hard invariant (`guardian.EnforceInvariant`):** AI may explain an incident or escalate (`warn` → `freeze` → `block_egress` → `kill`), but can **never** downgrade a deterministic verdict.
