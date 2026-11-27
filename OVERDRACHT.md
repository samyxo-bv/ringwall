# Ringwall: Handover

## Current Status (2026-11-27)

- **Repository:** `https://github.com/samyxo-bv/ringwall` (public, Apache-2.0).
- **Released:** `v0.1.0` (`main` @ `f3553ed`, approved `AKKOORD` by Claude Opus 5.5 across 5 adversarial review rounds).
- **In Progress (`feat/v0.2-self-healing`):** Full v0.2 upgrade adding:
  1. **Synchronous eBPF LSM pre-syscall blocking (`lsm/file_open` + `lsm/bprm_check_security`):** kernel `-EPERM` pre-read blocking on SSH private keys & pinned secret inodes (defeating hardlinks & source-renames), non-spoofable caller `(s_dev, i_ino)` allowlisting, and pre-exec blocking for zero-day virtual-patched binaries (with automatic fallback to `fentry/security_file_open` and syscall tracepoints). Enabled by default in the ISO (`lsm=lockdown,yama,integrity,apparmor,bpf`).
  2. **Deterministic CVE, CISA KEV, stale-library (`needrestart`), and sysctl/permission drift scanner (`internal/scanner`):** pure-Go dpkg/apk inventory, HTTPS OSV.dev + CISA KEV + offline advisory bundle support.
  3. **Self-healing host auto-patcher, zero-day virtual patcher & signed Ed25519 A/B immutable updater (`internal/patcher`):** security-only `apt-get --only-upgrade`, anti-lockout protected service restarts, TTL-bounded virtual patches (deterministic + optional uncensored AI proposal validated against hard anti-lockout blocklists + automatic upstream-fix revocation), and Ed25519-signed A/B slot staging with boot-counter automatic rollback.
  4. **Automated CI CVE scanning (`.github/workflows/security-scan.yml`)** + A/B manifest generation in `release.yml` + 15 live QEMU LSM + self-healing E2E assertions.

## Key Architecture Decisions

- **Strict privilege separation:** `/run/ringwall/api.token`, `/var/log/ringwall/audit.jsonl`, and `/var/lib/ringwall/ab-state.json` are `0600 root:root`.
- **Deterministic kernel wall first, AI second:** eBPF LSM (`-EPERM`) + YAML/virtual policy engine + `pidfd`/`cgroup.freeze` run first; uncensored AI Guardian explains/escalates or proposes declarative virtual patches (never raw C/shell, always anti-lockout validated).
- **CI runner isolation:** Public repo uses GitHub-hosted `ubuntu-latest` with 40-char SHA-pinned GitHub Actions only.
