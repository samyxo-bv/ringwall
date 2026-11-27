# Security Policy & Threat Model

## Honest Threat Model

Ringwall is a **defense-in-depth Linux runtime containment and local/uncensored AI triage system**. No OS or security daemon can promise "zero vulnerabilities".

### What Ringwall Detects & Contains
- **Prompt-injected or runaway AI coding/MCP agents** accessing private credentials (`~/.ssh/id_*`, `~/.aws/credentials`, `~/.kube/config`, GPG keys) — including `//home`, `/./`, `/proc/self/root`, `/proc/self/cwd`, `/dev/fd/<n>`, relative `openat(dirfd, ...)`, leaf symlinks, and directory symlinks across `PrivateTmp`/mount namespaces — or running recursive `rm` wipes (even without `-f`, with `--rec`, or expanded `/home/<user>`).
- **Common post-exploitation techniques:** reverse shell `execve` patterns (`/dev/tcp`, `nc -e`, `socat`), persistence writes (`openat`, `creat`, `renameat2` targeting `/etc/cron*`, `/etc/systemd/system/*`, `authorized_keys`), kernel module loading, `io_uring_setup` syscall-bypass attempts, and outbound C2 connections (`connect` + `sendto`).
- **Persistent rootfs compromise (Appliance ISO):** read-only SquashFS + ephemeral overlay wipes filesystem changes on reboot. On Linux 6.6+ hosts `kernel.io_uring_disabled = 2` disables `io_uring` via sysctl; on older kernels (such as Debian 12's 6.1 in the ISO), `sys_enter_io_uring_setup` is traced via eBPF and freezes the calling process (`RW-CORE-007`).
- **LLM failure modes:** model refusals on exploit telemetry (caught by live 4-point onboarding check and runtime refusal failover), single-model false negatives (mitigated by tiered/consensus fail-closed voting), and prompt injection embedded inside process arguments or filenames.
- **Unprivileged tamper attempts:** `/run/ringwall/api.token` and `/var/log/ringwall/audit.jsonl` are `0600 root:root`; monitored users cannot disable Ringwall or forge audit entries.

### Explicit Limitations & Non-Goals (Read Carefully!)
- **Asynchronous tracepoints (not pre-syscall blocking):** v0.1 uses Linux eBPF `tracepoint/syscalls/sys_enter_*` + fast userspace `pidfd_send_signal` (`SIGSTOP`/`SIGKILL`) and cgroup v2 freezer containment. For an `openat` read, the initial file read can complete before `SIGSTOP` lands — Ringwall freezes the process tree immediately afterward to stop subsequent exfiltration or follow-on actions. Synchronous pre-read blocking requires eBPF LSM (`file_open` / `bprm_check_security` with `CONFIG_BPF_LSM=y`), planned for v0.2.
- **`SIGSTOP` vs cgroup v2 freezer:** On a non-isolated interactive shell session, another same-UID process could theoretically send `SIGCONT` to a `SIGSTOP`-frozen sibling. Ringwall mitigates this by (1) freezing known AI-agent ancestors alongside the offending child, and (2) writing to root-owned `cgroup.freeze` whenever a workload runs in a dedicated container/agent cgroup (recommended for production agent sandboxing).
- **Shell-builtin pipelines:** Raw shell pipes (`curl url | sh`) executed directly in an interactive shell create separate `curl` and `sh` `execve` calls without a single combined command string; `RW-CORE-002` / `RW-AGENT-004` catch them when passed through `sh -c` / `bash -c` (which is how coding agents execute shell tools).
- **Audit log boundaries:** The SHA-256 hash chain detects in-place edits, deletions, or reordering of past entries by non-root attackers, and fails cleanly if tampered. A root-equivalent attacker with full disk control could truncate the tail or rewrite the entire log from genesis; forward logs off-host or anchor hashes externally for root-compromise forensics.
- **Cloud AI telemetry privacy:** When you opt into a cloud uncensored API (such as Venice.ai or OpenRouter), incident metadata (process names, paths, and command lines) is sent over HTTPS to that provider. Ringwall strips common tokens/passwords (`RedactSecrets`), but cannot guarantee zero secret leakage in arbitrary command strings — use **Local Ollama** or **llama.cpp** for strict offline privacy.
- **Hardlinks & path-based boundary:** v0.1 matches canonicalized paths (including component-wise symlink resolution). Preexisting hardlinks pointing to the same inode as a protected file are not caught by path matching alone; inode-based eBPF LSM `file_open` hooks are planned for v0.2.
- **Public health snapshot:** `/run/ringwall-status/status.json` exposes strictly non-sensitive aggregate counters (`sensor_mode`, `policy_count`, `dropped_events`, `incidents_total`) for local monitoring without revealing any tokens, paths, or rules.
- **Kernel 0-days, root compromise, CPU side-channels & firmware bugs:** Outside userspace daemon scope; pair with hardware virtualization (e.g., Qubes OS / Firecracker microVMs) for strict multi-tenant isolation.

## Security Invariants

1. **Deterministic Policy Wins:** `guardian.EnforceInvariant` guarantees no LLM output can downgrade a deterministic `warn`, `freeze`, `block_egress`, or `kill` verdict.
2. **Freeze First, Analyze Second:** High-risk processes are frozen via `pidfd`-verified `SIGSTOP` (and cgroup v2 freezer when isolated) before AI inference begins; slow AI responses can never overwrite an operator's decision.
3. **Root-Only Control Plane & Secrets:** Control API (`127.0.0.1:9443`) rejects non-loopback bindings by default, authenticates via a `0600 root:root` bearer token, requires HTTPS + explicit opt-in for remote AI APIs, and stores API keys in separate `0600` files (never inline in YAML).
4. **Zero Shell Execution in Enforcement:** `nftables` rules reject zoned/non-public IPs via `netip.Addr` and call `exec.Command("nft", ...)` directly.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories on `samyxo-bv/ringwall` rather than opening a public issue.
