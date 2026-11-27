# Ringwall

**by [Samyxo](https://www.samyxo.nl/)** &bull; [Project Website](https://samyxo-bv.github.io/ringwall/) &bull; [v0.2.0 Release](https://github.com/samyxo-bv/ringwall/releases/tag/v0.2.0) &bull; [Discussions](https://github.com/samyxo-bv/ringwall/discussions)

[![CI](https://github.com/samyxo-bv/ringwall/actions/workflows/ci.yml/badge.svg)](https://github.com/samyxo-bv/ringwall/actions/workflows/ci.yml)
[![Security Scan](https://github.com/samyxo-bv/ringwall/actions/workflows/security-scan.yml/badge.svg)](https://github.com/samyxo-bv/ringwall/actions/workflows/security-scan.yml)
[![Release](https://img.shields.io/github/v/release/samyxo-bv/ringwall)](https://github.com/samyxo-bv/ringwall/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Fail-closed Linux eBPF LSM runtime guardian, automated CVE/KEV & drift self-healer (host auto-patching, TTL-bounded zero-day virtual patching, signed Ed25519 A/B immutable updates), and refusal-resistant uncensored AI Guardian — installable on any Linux host and shipped as a live QEMU-verified bootable immutable ISO.**

> **Security honesty upfront:** No operating system has "zero vulnerabilities", and an LLM must **never** be your primary security boundary or blindly live-patch unknown zero-day source code in production. Ringwall enforces **deterministically inside the Linux kernel first** (synchronous fail-closed eBPF LSM hooks returning `-EPERM` before a single byte is read or executed, with automatic `fentry`/`tracepoint`/`procfs` fallback + `pidfd` `SIGSTOP`/`SIGKILL` + cgroup v2 freezer & `nftables`), automates **verified CVE patching & temporary zero-day virtual patching**, and layers an **uncensored / abliterated AI Guardian** on top to explain incidents and propose validated containment rules. **AI can never downgrade a deterministic verdict or bypass anti-lockout guardrails.**

---

## Documentation

| Guide | What it covers |
|---|---|
| **[Getting Started](docs/getting-started.md)** | Install from release tarball, build from source, enable `lsm=...,bpf`, Guided Setup Wizard, SSH key opt-in, troubleshooting |
| **[Architecture](docs/architecture.md)** | 3-tier eBPF LSM/fentry/tracepoint sensor, fail-closed ringbuf flood design, `pidfd`/cgroup enforcement, privilege boundaries, AI pool |
| **[Configuration & Policies](docs/configuration-and-policies.md)** | Complete `ringwall.yaml` reference, all 13 built-in rules (`RW-CORE`/`RW-AGENT`/`RW-NET`), 11 drift checks (`RW-DRIFT`), custom YAML rules |
| **[Self-Healing & A/B Updates](docs/self-healing-and-ab-updates.md)** | CVE/KEV/stale-library scanner, offline advisory JSON schema, auto-patcher, zero-day virtual patch anti-lockout invariants, Ed25519 A/B updates |
| **[CLI & HTTP API](docs/cli-and-api.md)** | Every `ringwalld` flag, `ringwallctl` subcommand, and all 15 authenticated REST/SSE endpoints with `curl` examples |
| **[Immutable Appliance ISO](docs/immutable-iso.md)** | Building (`make iso`), embedding a GGUF model (`--with-model`), booting in QEMU/USB, and all 16 live QEMU security assertions |
| **[Security Policy & Threat Model](SECURITY.md)** | Honest threat model, explicit limitations, security invariants, and private vulnerability reporting |

---

## Quick Start (Choose One Path)

### Option A — Prebuilt Linux Release (`v0.2.0`)

```bash
VERSION=v0.2.0
BASE="https://github.com/samyxo-bv/ringwall/releases/download/${VERSION}"
curl -fsSLO "${BASE}/ringwall-${VERSION}-linux-amd64.tar.gz"
curl -fsSLO "${BASE}/SHA256SUMS.txt"
grep "linux-amd64.tar.gz" SHA256SUMS.txt | sha256sum -c -

mkdir -p ringwall-install && tar -xzf "ringwall-${VERSION}-linux-amd64.tar.gz" -C ringwall-install
cd ringwall-install && sudo ./packaging/install.sh
```

### Option B — Build from Source (Linux)

```bash
git clone https://github.com/samyxo-bv/ringwall.git
cd ringwall
make build                  # compiles ebpf/ringwall.bpf.c + static binaries with embedded eBPF
sudo ./packaging/install.sh # installs binaries, policies, sysctl profile & ringwalld.service
```

### Option C — Boot the Immutable Appliance ISO (`194 MB`)

```bash
curl -fsSLO https://github.com/samyxo-bv/ringwall/releases/download/v0.2.0/ringwall-v0.2.0-appliance-amd64.iso
qemu-system-x86_64 -m 1536 -smp 2 -nographic -cdrom ringwall-v0.2.0-appliance-amd64.iso -boot d
```

### First Checks After Install

```bash
# Guided beginner Setup Wizard (detects RAM/GPU/Ollama & runs a live 4-point refusal test):
sudo ringwallctl setup

# Live CVE/KEV + stale-library + kernel drift scan & dry-run patch plan:
sudo ringwallctl scan
sudo ringwallctl patch --dry-run

# Verify kernel eBPF LSM status, built-in simulations, and SHA-256 audit hash chain:
sudo ringwallctl status
sudo ringwallctl simulate
sudo ringwallctl verify-log
```

Open the local Web UI at `http://127.0.0.1:9443` (zero external CDNs) using the root-only bearer token from `sudo cat /run/ringwall/api.token`.

> **Host SSH key workflow (zero-exemption default):** By default, Ringwall blocks *all* direct on-disk SSH private-key opens (`sensor.lsm_allowed_ssh_exes: []` and zero `exclude_exe_paths` on `RW-AGENT-001`) to prevent same-UID `ssh -F` and rogue `SSH_AUTH_SOCK` `ssh-add` exfiltration. For interactive host SSH, prefer FIDO2/hardware keys, or explicitly opt your local binaries (with passphrase-protected keys) into `sensor.lsm_allowed_ssh_exes` in `/etc/ringwall/ringwall.yaml` and `exclude_exe_paths` in `/etc/ringwall/policies.d/10-ai-agent-guard.yaml` (exact snippet in [Getting Started](docs/getting-started.md#host-ssh-key-workflow-zero-exemption-default)).

---

## Architecture (v0.2)

```
  Linux Kernel — Tier 1 Fail-Closed Synchronous eBPF LSM
       │  • lsm/file_open: pre-read -EPERM on SSH keys & pinned secret inodes (fail-closed even under floods)
       │  • lsm/mmap_file + lsm/ptrace_access_check + task->ptrace: blocks LD_PRELOAD/PKCS11/strace SSH hijacks
       │  • lsm/bprm_check_security: pre-exec -EPERM on zero-day virtual-patched binaries (O_NOFOLLOW + i_generation)
       │  • Automatic fallback: fentry/security_file_open (bpf_d_path) -> syscall tracepoints -> procfs
       │  • 4 MiB ringbuf + per-CPU drop counter (RW-SYS-DROP) + exec/rename/link/symlink/connect/io_uring
       ▼
  Layer 1 — Deterministic Policy Engine & Self-Healing Engine (0 ms)
       │  • 13 built-in rules (core hardening, AI-agent guard, egress) + persisted TTL-bounded Virtual Patches
       │  • Continuous CVE/KEV/drift/stale-lib scanner (OSV.dev + CISA KEV + airgapped offline DB)
       │  • Host security-only auto-patcher (apt-get --only-upgrade + protected service restarts + RefreshAndSync)
       │  • Signed Ed25519 A/B immutable slot updater (experimental for disk-installed GRUB/systemd-boot)
       │  • Tamper-evident SHA-256 hash-chained audit log (0600 root)
       ▼
  Layer 2 — Bounded Multi-Model Uncensored AI Guardian (Ollama / llama.cpp / Venice / OpenRouter)
       │  • Secret-redacted telemetry, prompt-injection defense, refusal failover, virtual-patch proposals
       │  • HARD INVARIANT: AI may explain or escalate, NEVER downgrade verdicts or bypass anti-lockout
       ▼
  Root-Only Admin Control Plane (127.0.0.1:9443, 0600 bearer token)
       • Web UI (Live Monitor + CVE Scanner & Self-Healing + Guided Setup Wizard, zero external CDNs)
       • CLI (`sudo ringwallctl setup | status | scan | patch | vpatches | ab-status | simulate | verify-log`)
```

---

## Why an Uncensored (Abliterated) AI Model?

Standard cloud AI models often fail as cybersecurity daemons because their safety filters trigger on real threat logs. Feed them a reverse shell (`bash -i >& /dev/tcp/...`) or an obfuscated exploit payload and they reply *"I cannot assist with malware"* — leaving your defense blind right when an attack happens.

An **abliterated / uncensored model** has those false-positive refusals removed so it inspects defensive security telemetry honestly, classifies real threats, and explains them clearly in plain language. Ringwall's Setup Wizard (`sudo ringwallctl setup` or the Web UI) runs a **live 4-point security & refusal test** before saving:

1. **Reachable & API Key Valid**
2. **Zero Refusal on Security Telemetry** (tests a safe fake reverse shell — immediately catches censored models)
3. **Valid Strict JSON Verdict Format**
4. **Threat Actually Caught** (confirms the model scores high risk instead of saying `allow`)

### Supported Uncensored AI Providers (Pick One — or Combine Two)

| Provider | Where it runs | Privacy | GPU / RAM needed | Cost | Recommended Uncensored Models |
|---|---|---|---|---|---|
| **Ollama** | Local (your machine) | **Maximum** — 100% offline | 8 GB RAM (3B) / 16 GB+ or GPU (7B–8B) | Free | `huihui_ai/qwen2.5-coder-abliterated:7b`, `dolphin-llama3:8b`, `qwen2.5-coder:3b` |
| **llama.cpp (`llama-server`)** | Local GGUF or self-hosted | **Maximum** — 100% offline | Optional GPU / CPU GGUF | Free | `foundation-sec-8b`, `qwen2.5-coder-7b-abliterated` |
| **Venice.ai API** | Privacy-first cloud | **High** — zero-data-retention API (secrets redacted before send) | **None** | Pay-as-you-go / Pro | `venice-uncensored-1-2`, `hermes-3-llama-3.1-405b` |
| **OpenRouter API** | Multi-provider cloud | Depends on route (secrets redacted before send) | **None** | Pay-per-token | `cognitivecomputations/dolphin-mistral-24b-venice-edition:free`, `nousresearch/hermes-3-llama-3.1-70b` |
| **Custom OpenAI-Compatible** | Your own vLLM / cloud API | Under your control | Depends on host | Depends on host | Any uncensored OpenAI-compatible model |

---

## Live QEMU & Host Verification (On Every CI & Release Run)

Every CI run verifies **zero-exemption default blocking** (`ssh -F` and rogue `SSH_AUTH_SOCK` `ssh-add` -> `Operation not permitted`), **opt-in `ssh-keygen` positive control + `lsm/mmap_file` (`LD_PRELOAD` main/pthread/fork blocked at `ld.so` map time) + pre-exec `PTRACE_TRACEME` (`task->ptrace != 0` -> `Operation not permitted`)**, and `lsm/bprm_check_security` (live `tmpfs` + verified `ext4` `FS_IOC_GETVERSION` `i_generation` virtual-patch block & revoke) on the Linux host, runs `govulncheck@v1.10.0` (0 CVEs), AND boots the freshly built `.iso` headless in QEMU as unprivileged `operator` to prove **16 live assertions** inside the VM (full table in [Immutable Appliance ISO](docs/immutable-iso.md#all-16-live-qemu-security-assertions-isotest-qemush)).

---

## Security Policy & License

- Read [SECURITY.md](SECURITY.md) for our honest threat model, explicit limitations, and private vulnerability reporting process.
- Apache License 2.0 — see [LICENSE](LICENSE). Built and open-sourced by [Samyxo B.V.](https://www.samyxo.nl/) ([github.com/samyxo-bv](https://github.com/samyxo-bv)).
