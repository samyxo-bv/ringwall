# Ringwall: Handover

## Current Status (2026-11-27)

- **Repository:** `https://github.com/samyxo-bv/ringwall` (public, Apache-2.0).
- **Branch / PR:** `feat/v0.1-mvp` (PR #1) — all P0-1, P1-1..P1-7, and key P2 findings from independent Claude Opus 5.5 security review (`thr_p8xe9zd4tv`) have been remediated.
- **Open:** Verify green CI (eBPF + `go test -mod=readonly -race` + live root host test + 8 live QEMU ISO assertions), run Claude Opus 5.5 re-review on new HEAD, merge PR #1, and tag `v0.1.0` release with verified `.iso`.

## Key Architecture Decisions

- **Strict privilege separation:** `/run/ringwall/api.token` and `/var/log/ringwall/audit.jsonl` are strictly `0600 root:root`. Monitored unprivileged users (`operator` in ISO, password locked, no sudo) cannot read the token or disable enforcement. Strictly non-sensitive health metrics are exposed read-only in `/run/ringwall-status/status.json`.
- **Deterministic wall first, AI second:** eBPF tracepoints (`execve`, `execveat`, `openat`, `openat2`, `open`, `connect`, `sendto`) + canonical path resolution + `pidfd`-verified `SIGSTOP`/`SIGKILL` & cgroup v2 freezer run first; multi-model uncensored AI Guardian explains/escalates only and can never downgrade a deterministic verdict.
- **CI runner isolation:** Public repo uses GitHub-hosted `ubuntu-latest` with SHA-pinned GitHub Actions.
