# Ringwall

Centrale instructies: samyxo-bv/dotfiles (al geladen via sync.ps1). Ontbreken ze in je sessie (bijv. Cloud), lees dan `claude/CLAUDE.md` uit die repo (`gh repo clone samyxo-bv/dotfiles`).

## Project Overview

Ringwall (`samyxo-bv/ringwall`) is a **public open-source** Linux runtime security guardian combining:
1. Deterministic kernel/OS enforcement (eBPF CO-RE + procfs fallback, process-lineage policy engine, `SIGSTOP`/`SIGKILL`/`nftables` containment).
2. Prompt-injection-hardened local AI triage (Ollama / `llama.cpp` on localhost, with deterministic fallback).
3. A reproducible, immutable, hardened bootable Linux ISO (`iso/build-iso.sh`) verified via live QEMU attack tests (`iso/test-qemu.sh`).

## Public Repo Hygiene

- This repository is **PUBLIC**. Never commit internal hostnames, private IP addresses, customer names, credentials, tokens, or secrets.
- CI MUST use GitHub-hosted `ubuntu-latest` runners (free and isolated for public repos) — **NEVER** self-hosted runners on public PR workflows.

## Build & Test

- Unit & race tests: `go test -race ./...`
- Compile eBPF probe + static Linux binaries: `make build`
- Build immutable bootable ISO (Linux with root/debootstrap/squashfs-tools/xorriso): `sudo ./iso/build-iso.sh`
- Live QEMU ISO attack verification: `./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso`

## Code Review Rules

Every PR touching security logic, eBPF, policy evaluation, enforcement, AI triage, or ISO hardening requires an independent review from a different model family. Always report P0 and P1 issues:

- **P0 (blocking):**
  - Any path where AI output can downgrade, bypass, or override a deterministic `deny`, `freeze`, or `kill` verdict.
  - Command injection or shell interpolation in enforcement (`nftables`, signals, subprocesses) or ISO build scripts.
  - Prompt injection allowing attacker-controlled telemetry (`argv`, `comm`, `path`) to execute actions outside the bounded policy broker.
  - Unauthenticated or non-localhost default exposure of the control API / dashboard, or remote AI egress enabled by default.
  - Unbounded eBPF memory access, missing `bpf_ringbuf_discard` paths, or infinite self-monitoring loops.
  - Leaked secrets, private keys, or default root/SSH passwords in the ISO.
- **P1 (fix before merge):**
  - Race conditions in incident state, lineage cache, or audit log hash-chaining.
  - Broken fallback when eBPF/BTF or local LLM is unavailable.
  - Failing or skipped tests (`go test -race ./...` and live QEMU ISO attack test).
