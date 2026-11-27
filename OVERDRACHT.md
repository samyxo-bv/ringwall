# Ringwall: Handover

## Current Status (2026-11-27)

- **Repository:** `https://github.com/samyxo-bv/ringwall` (public, Apache-2.0).
- **Branch / PR:** `feat/v0.1-mvp` (PR #1) — all P0-1, P1-1..P1-7, and re-review P1-A..P1-E + P2 findings from Claude Opus 5.5 (`thr_p8xe9zd4tv`, `thr_wjgxpdp3ji`) remediated.
- **Open:** Verify green CI (10 live QEMU ISO assertions incl. `io_uring_setup`, `//home`, `/proc/self/cwd`, `/tmp/d` directory symlink, `rm -r /usr`), final Claude Opus 5.5 re-review `AKKOORD`, merge PR #1, and tag `v0.1.0`.

## Key Architecture Decisions

- **Strict privilege separation:** `/run/ringwall/api.token` and `/var/log/ringwall/audit.jsonl` are strictly `0600 root:root`. Monitored unprivileged users (`operator` in ISO, password locked, no sudo) cannot read the token or disable enforcement. Strictly non-sensitive health metrics are exposed read-only in `/run/ringwall-status/status.json`.
- **Deterministic wall first, AI second:** eBPF tracepoints (`execve`, `execveat`, `openat`, `openat2`, `open`, `connect`, `sendto`) + canonical path resolution + `pidfd`-verified `SIGSTOP`/`SIGKILL` & cgroup v2 freezer run first; multi-model uncensored AI Guardian explains/escalates only and can never downgrade a deterministic verdict.
- **CI runner isolation:** Public repo uses GitHub-hosted `ubuntu-latest` with SHA-pinned GitHub Actions.
