# Ringwall

## Project Overview

Ringwall (`samyxo-bv/ringwall`) is a **public open-source** Linux runtime security guardian combining:
1. Deterministic kernel/OS enforcement (eBPF tracepoint sensor for `execve`, `execveat`, `openat`, `openat2`, `open`, `connect`, `sendto` with automatic `procfs` fallback, canonical path & process-lineage policy engine, `pidfd`-verified `SIGSTOP`/`SIGKILL`, cgroup v2 freezer, and `nftables` containment).
2. Refusal-resistant, prompt-injection-hardened AI Guardian (multi-model local Ollama / `llama.cpp` or opt-in uncensored cloud APIs like Venice.ai / OpenRouter, with beginner Setup Wizard and live 4-point refusal check).
3. An automated, immutable, hardened bootable Linux ISO (`iso/build-iso.sh`) verified via live QEMU attack tests (`iso/test-qemu.sh`).

## Public Repo Hygiene

- This repository is **PUBLIC**. Never commit internal hostnames, private IP addresses, customer names, credentials, tokens, or private repository references.
- CI MUST use GitHub-hosted `ubuntu-latest` runners with SHA-pinned actions — **NEVER** self-hosted runners on public PR workflows.

## Build & Test

- Verify modules: `go mod verify`
- Unit & race tests: `go test -mod=readonly -race ./...`
- Compile eBPF probe + static Linux binaries: `make build`
- Build immutable bootable ISO (Linux with root/debootstrap/squashfs-tools/xorriso): `sudo ./iso/build-iso.sh`
- Live QEMU ISO attack verification: `./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso`

## Code Review Rules

Every PR touching security logic, eBPF, policy evaluation, enforcement, AI triage, or ISO hardening requires an independent review from a different model family. Always report P0 and P1 issues:

- **P0 (blocking):**
  - Any path where AI output can downgrade, bypass, or override a deterministic `deny`, `freeze`, or `kill` verdict.
  - Monitored unprivileged users able to read the admin API token, disable enforcement, or tamper with audit logs.
  - Command injection or shell interpolation in enforcement (`nftables`, signals, subprocesses) or ISO build scripts.
  - Prompt injection allowing attacker-controlled telemetry (`argv`, `comm`, `path`) to execute actions outside the bounded policy broker.
  - Unauthenticated or non-localhost default exposure of the control API / dashboard, or remote AI egress enabled by default.
  - Unbounded eBPF memory access, missing `bpf_ringbuf_discard` paths, or infinite self-monitoring loops.
  - Leaked secrets, private keys, or empty/default passwords in the ISO.
- **P1 (fix before merge):**
  - Race conditions in incident state, operator decisions vs AI goroutines, PID reuse, lineage cache, or audit log hash-chaining.
  - Trivial policy bypasses (unnormalized paths, symlinks, `/proc/self/root`, comm spoofing, argv flag variations).
  - Silent telemetry drops without drop counters/alerts.
  - Failing or skipped tests (`go test -mod=readonly -race ./...` and live QEMU ISO attack test).
