# Ringwall: Handover

## Current Status (2026-11-27)

- **Repository:** `https://github.com/samyxo-bv/ringwall` (public, Apache-2.0).
- **Latest Release:** **`v0.2.0`** (`main` @ `6ba19f2`, published with verified `ringwall-v0.2.0-appliance-amd64.iso` (194.3 MB), `ringwall-v0.2.0-linux-amd64.tar.gz` (7.1 MB), `ringwall-v0.2.0-ab-manifest.json`, and `SHA256SUMS.txt`).
- **Independent Security Reviews:**
  - `v0.1.0` (PR #1): approved `AKKOORD` by Claude Opus 5.5 across 5 adversarial rounds.
  - `v0.2.0` (PR #2): approved `AKKOORD` (0 P0, 0 P1) by `claude-code/claude-opus-5-5` across 5 adversarial rounds on exact HEAD `6659198` (merged at `6ba19f2`).
- **What `v0.2.0` Ships:**
  1. **Fail-Closed Synchronous eBPF LSM (`ebpf/ringwall.bpf.c`, `internal/sensor/`):** `lsm/file_open` (per-CPU scratch BEFORE `bpf_ringbuf_reserve`, fail-closed `-EPERM` even under floods, pinned secret inodes, zero-exemption SSH default `lsm_allowed_ssh_exes: []`, `task->ptrace != 0` revocation), `lsm/mmap_file` (`-EPERM` on non-root / `mode & 0022` `PROT_EXEC` mappings), `lsm/ptrace_access_check`, and `lsm/bprm_check_security` (`O_PATH|O_NOFOLLOW` + `S_IFREG` + `FS_IOC_GETVERSION` `i_generation` + live protected-inode refresh).
  2. **Deterministic CVE, CISA KEV, Stale-Library & Drift Scanner (`internal/scanner/`):** pure-Go dpkg/apk inventory, deleted `.so` `/proc/*/maps` detection, baseline sysctl/0600 drift audit, opt-in HTTPS OSV.dev + CISA KEV (with pagination/truncation detection), and airgapped offline JSON bundle support.
  3. **Self-Healing Auto-Patcher, TTL-Bounded Zero-Day Virtual Patcher & Signed Ed25519 A/B Updater (`internal/patcher/`, `internal/guardian/virtual_patch.go`, `internal/daemon/selfheal.go`):** security-only `apt-get --only-upgrade` (zero shell), protected stale-service restarts, live `(dev, ino)` anti-lockout virtual patch validation + runtime `vpExeGuard` in `policy.Engine` + `0600` JSON persistence outside `policy_dirs` + fail-closed `Reconcile` + `RefreshAndSync()`, and Ed25519-signed A/B slot staging with `/proc/cmdline` `ringwall.slot=A|B` boot-confirmed promotion/rollback.
  4. **CI & Documentation:** `govulncheck@v1.10.0` (0 CVEs, Go 1.27), 40-char SHA-pinned GitHub Actions, live Ubuntu host LSM proofs (`ssh -F`, rogue `SSH_AUTH_SOCK` `ssh-add`, `ext4` `FS_IOC_GETVERSION`, `bprm`, opt-in positive control + `LD_PRELOAD` + `PTRACE_TRACEME`), 16 live QEMU ISO assertions, and full `docs/` reference documentation.

## Key Architecture Decisions

- **Strict privilege separation:** `/run/ringwall/api.token`, `/var/log/ringwall/audit.jsonl`, `/var/lib/ringwall/virtual-patches.json`, and `/var/lib/ringwall/ab-state.json` are `0600 root:root`.
- **Zero-exemption SSH private-key default:** `sensor.lsm_allowed_ssh_exes: []` and zero `exclude_exe_paths` on `RW-AGENT-001` by default (defeats `ssh -F` and rogue `SSH_AUTH_SOCK` `ssh-add`); hosts opt in explicitly if required.
- **Deterministic kernel wall first, AI second:** eBPF LSM (`-EPERM`) + YAML/virtual policy engine + `pidfd`/`cgroup.freeze` execute first; uncensored AI Guardian explains/escalates or proposes declarative virtual patches (never raw C/shell, always anti-lockout validated).
- **CI runner isolation:** Public repo uses GitHub-hosted `ubuntu-latest` with 40-char SHA-pinned GitHub Actions only.
- **Release signing follow-up (optional for `v0.2.1`+):** Configure GitHub Actions secret `RINGWALL_AB_SIGNING_KEY_B64` (Ed25519 private key from `ringwallctl ab-keygen`) so future release manifests include a non-empty `signature_ed25519_b64`.
