# Ringwall

**Deterministic Linux runtime guardian (synchronous eBPF LSM + process-lineage policy engine), automated CVE/KEV scanner & self-healing patcher (host auto-patching, TTL-bounded zero-day virtual patching, signed Ed25519 A/B immutable updates), and refusal-resistant uncensored AI Guardian — installable on any Linux host and shipped as a live-verified bootable immutable ISO.**

> **Security honesty upfront:** No operating system has "zero security issues", and an LLM must **never** be your primary security boundary or blindly compile patches into production. Ringwall enforces **deterministically inside the Linux kernel first** (synchronous eBPF `lsm/file_open` + `lsm/bprm_check_security` returning `-EPERM` before a single byte is read, with automatic `fentry`/`tracepoint` fallback + `pidfd` `SIGSTOP`/`SIGKILL` + cgroup v2 freezer & `nftables`), automates **verified CVE patching & temporary zero-day virtual patching**, and layers an **uncensored / abliterated AI Guardian** on top to explain incidents and propose validated containment rules. **AI can never downgrade a deterministic verdict or bypass anti-lockout guardrails.**

---

## Why an Uncensored (Abliterated) AI Model?

Standard cloud AI models (like default ChatGPT or Claude) are often **unsuitable as cybersecurity daemons** because their safety filters trigger on real threat logs. Feed them a reverse shell (`bash -i >& /dev/tcp/...`) or an obfuscated exploit payload and they reply *"I cannot assist with malware"* — leaving your defense blind right when an attack happens.

An **abliterated / uncensored model** has those false-positive refusals removed so it inspects defensive security telemetry honestly, classifies real threats, and explains them clearly in plain language.

Ringwall ships a **step-by-step Setup Wizard** (`sudo ringwallctl setup` and the **Web Setup Wizard** at `http://127.0.0.1:9443`) so **anyone — even non-technical users** — can pick a provider, paste an API key or pick a local model, and run a **live 4-point security & refusal test** before saving:

1. **Reachable & API Key Valid**
2. **Zero Refusal on Security Telemetry** (tests a safe fake reverse shell — immediately catches censored models!)
3. **Valid Strict JSON Verdict Format**
4. **Threat Actually Caught** (confirms the model scores high risk instead of saying `allow`)

---

## Supported Uncensored AI Providers (Pick One — or Combine Two)

| Provider | Where it runs | Privacy | GPU / RAM needed | Cost | Recommended Uncensored Models |
|---|---|---|---|---|---|
| **Ollama** | Local (your machine) | **Maximum** — 100% offline | 8 GB RAM (3B) / 16 GB+ or GPU (7B–8B) | Free | `huihui_ai/qwen2.5-coder-abliterated:7b`, `dolphin-llama3:8b`, `qwen2.5-coder:3b` |
| **llama.cpp (`llama-server`)** | Local GGUF or self-hosted | **Maximum** — 100% offline | Optional GPU / CPU GGUF | Free | `foundation-sec-8b`, `qwen2.5-coder-7b-abliterated` |
| **Venice.ai API** | Privacy-first cloud | **High** — zero-data-retention API (telemetry secrets redacted before send) | **None** (runs on any tiny VM/laptop) | Pay-as-you-go / Pro | `venice-uncensored-1-2`, `hermes-3-llama-3.1-405b` |
| **OpenRouter API** | Multi-provider cloud | Depends on route (secrets redacted before send) | **None** | Pay-per-token | `cognitivecomputations/dolphin-mistral-24b-venice-edition:free`, `nousresearch/hermes-3-llama-3.1-70b` |
| **Custom OpenAI-Compatible** | Your own vLLM / cloud API | Under your control | Depends on host | Depends on host | Any uncensored OpenAI-compatible model |

---

## Architecture (v0.2)

```
  Linux Kernel — Tier 1 Fail-Closed Synchronous eBPF LSM
       │  • lsm/file_open: pre-read -EPERM on SSH keys & pinned secret inodes (fail-closed even under floods)
       │  • lsm/mmap_file + lsm/ptrace_access_check: defeats LD_PRELOAD, PKCS11Provider & ptrace SSH hijacks
       │  • lsm/bprm_check_security: pre-exec -EPERM on zero-day virtual-patched binaries
       │  • Automatic fallback: fentry/security_file_open (bpf_d_path) -> syscall tracepoints -> procfs
       │  • 4 MiB ringbuf + per-CPU drop counter (RW-SYS-DROP) + exec/rename/link/symlink/connect/io_uring
       ▼
  Layer 1 — Deterministic Policy Engine & Self-Healing Engine (0 ms)
       │  • Core hardening + AI-agent guard + persisted TTL-bounded Zero-Day Virtual Patches (inode anti-lockout)
       │  • Continuous CVE/KEV/drift/stale-lib scanner (OSV.dev + CISA KEV + offline DB)
       │  • Host security-only auto-patcher (apt-get --only-upgrade + stale service restart + anti-lockout)
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

## Quick Start (Any Linux Host)

```bash
git clone https://github.com/samyxo-bv/ringwall.git
cd ringwall
make build
sudo ./packaging/install.sh

# Interactive beginner Setup Wizard (detects RAM/GPU/Ollama & live-tests your model):
sudo ringwallctl setup

# Live CVE/KEV + stale-library + kernel drift scan & dry-run patch plan:
sudo ringwallctl scan
sudo ringwallctl patch --dry-run

# Verify runtime protection and audit log integrity:
sudo ringwallctl status
sudo ringwallctl simulate
sudo ringwallctl verify-log
```

Open the local web UI at `http://127.0.0.1:9443` using the root-only bearer token from `sudo cat /run/ringwall/api.token`.

---

## Bootable Immutable Hardened ISO (with Synchronous eBPF LSM)

Ringwall ships an automated **hybrid BIOS + UEFI bootable Linux appliance ISO** (`iso/build-iso.sh`) built on minimal Debian Bookworm:

- **Synchronous eBPF LSM enabled at boot:** `lsm=lockdown,yama,integrity,apparmor,bpf` + `lockdown=integrity` + `init_on_alloc=1` + `init_on_free=1` + `slab_nomerge` + `pti=on` + `randomize_kstack_offset=on` + `kernel.unprivileged_userns_clone = 0`.
- **Read-only SquashFS root filesystem** + ephemeral RAM overlay + signed Ed25519 A/B manifest support (`ringwallctl ab-keygen | ab-sign | ab-verify`).
- **Default-deny `nftables` firewall** with dynamic `blocked_v4` / `blocked_v6` sets driven by `ringwalld`.
- **Strict privilege isolation:** no SSH server, locked `root` and `operator` passwords, monitored `operator` user has zero access to `/run/ringwall/api.token` (`0600 root`) or `/var/log/ringwall/audit.jsonl`.
- **Optional air-gapped AI model bundle:** pass `--with-model /path/to/model.gguf`.

### Live QEMU & Host Verification (16 Live ISO + Host LSM Assertions on Every CI & Release Run)

Every CI run verifies `lsm/mmap_file` (`LD_PRELOAD` into `/usr/bin/ssh-keygen` -> `EPERM`) and `lsm/bprm_check_security` (live virtual-patch block & revoke) on the Linux host, AND boots the freshly built `.iso` headless in QEMU as unprivileged `operator` to prove live inside the VM:
1. Read-only SquashFS + no `sshd`; `open_hook: lsm/file_open`, `lsm_enforce_active: true`, and `ringwall.slot=A`.
2. Monitored `operator` cannot read `/run/ringwall/api.token` or `/var/log/ringwall/audit.jsonl` and gets HTTP `401`.
3. Direct SSH key read, `/usr/../home` traversal, `//home` traversal, **hardlinks (preexisting + new)**, **spoofed `/tmp/ssh` copies**, directory symlinks, cwd-relative opens, non-`/home` dot-paths (`/tmp/alt/.ssh/id_ed25519`), and **reads during a live UDP ringbuf-saturation flood** are **ALL blocked synchronously by the kernel with `EPERM` (0 bytes leaked)**.
4. `USERNS_SYSCTL=0` blocks unprivileged `unshare -Ur chroot`.
5. `io_uring_setup` (syscall 425), `SYS_rename` & `os.symlink` persistence into `authorized_keys`, `rm --r /usr`, `cd / && rm -r usr`, and `/dev/tcp` reverse shells are all caught and frozen in **`T (stopped)`**.
6. Ed25519 A/B manifest `ab-keygen` / `ab-sign` / `ab-verify` passes and rejects tampering; `dropped_events: 0` under normal load.

---

## Security Policy & Threat Model

Read [SECURITY.md](SECURITY.md) for our honest threat model, explicit limitations, and private vulnerability reporting process.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Built and open-sourced by [Samyxo B.V.](https://github.com/samyxo-bv).
