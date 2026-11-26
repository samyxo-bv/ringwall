# Security Policy & Threat Model

## Honest Threat Model

Ringwall is a **defense-in-depth Linux runtime containment and local/uncensored AI triage system**. No OS or security daemon can promise "zero vulnerabilities".

### What Ringwall Protects Against
- **Prompt-injected or runaway AI coding/MCP agents** reading private credentials (`~/.ssh/id_*`, `~/.aws/credentials`, `~/.kube/config`, GPG keys) or executing destructive commands (`rm -rf /`).
- **Common post-exploitation techniques:** reverse shells (`/dev/tcp`, `nc -e`, `socat`), `curl | sh`, persistence writes (`/etc/cron*`, `/etc/systemd/system/*`, `authorized_keys`), kernel module loading, and outbound C2 connections.
- **Persistent rootfs compromise (Appliance ISO):** read-only SquashFS + ephemeral overlay wipes filesystem changes on reboot.
- **LLM failure modes:** model refusals on exploit telemetry (caught by live 4-point onboarding check and runtime refusal failover), single-model false negatives (mitigated by tiered/consensus fail-closed voting), and prompt injection embedded inside process arguments or filenames.
- **Silent log tampering:** SHA-256 hash-chained JSONL audit log detects edits, deletions, or reordering.

### Explicit Non-Goals (Out of Scope)
- **Kernel 0-days & root-equivalent attacker with `CAP_SYS_ADMIN`:** once an attacker executes arbitrary code in Ring 0, any in-OS daemon can be bypassed. Use hardware virtualization (e.g., Qubes OS / Firecracker microVMs) for strict multi-tenant isolation.
- **CPU side-channels & firmware/UEFI/ME vulnerabilities:** mitigated at hardware/firmware level, not userspace.
- **Synchronous pre-syscall blocking (eBPF LSM):** v0.1 uses eBPF `tracepoint/syscalls/sys_enter_*` + fast userspace `SIGSTOP`/`SIGKILL` containment for maximum kernel portability without requiring `CONFIG_BPF_LSM=y` boot flags. Tightening to eBPF LSM `bprm_check_security` / `file_open` hooks is planned for v0.2.

## Security Invariants

1. **Deterministic Policy Wins:** `guardian.EnforceInvariant` guarantees no LLM output can downgrade a deterministic `warn`, `freeze`, `block_egress`, or `kill` verdict.
2. **Freeze First, Analyze Second:** High-risk processes receive `SIGSTOP` immediately before AI inference begins.
3. **Localhost-Only & HTTPS-Only Remote Opt-In:** Control API (`127.0.0.1:9443`) rejects non-loopback bindings by default; remote AI APIs require explicit opt-in and HTTPS, and store API keys in separate `0600` files (never inline in YAML).
4. **Zero Shell Execution in Enforcement:** `nftables` rules use validated `netip.Addr` and direct `exec.Command("nft", ...)` argv calls — never `sh -c`.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories on `samyxo-bv/ringwall` rather than opening a public issue.
