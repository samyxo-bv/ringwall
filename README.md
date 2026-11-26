# Ringwall

**Deterministic Linux runtime guardian (eBPF + process-lineage policy engine) with a refusal-resistant, uncensored AI Guardian — beginner-friendly guided setup, installable on any Linux host, and shipped as a reproducible immutable bootable ISO.**

> **Security honesty upfront:** No operating system has "zero security issues", and an LLM must **never** be your primary security boundary. Ringwall enforces **deterministically at kernel/OS speed first** (`eBPF` + `SIGSTOP`/`SIGKILL` + `nftables`), and layers an **uncensored / abliterated AI Guardian** on top to explain incidents in plain language, analyze obfuscated attacks, and escalate ambiguous threats. **The AI can never downgrade a deterministic block or freeze.**

---

## Why an Uncensored (Abliterated) AI Model?

Standard cloud AI models (like default ChatGPT or Claude) are often **terrible as cybersecurity daemons** because their safety filters trigger on real threat logs. Feed them a reverse shell (`bash -i >& /dev/tcp/...`) or an obfuscated exploit payload and they reply *"I cannot assist with malware"* — leaving your defense blind right when an attack happens.

An **abliterated / uncensored model** has those false-positive refusals removed so it inspects defensive security telemetry honestly, classifies real threats, and explains them clearly in human language.

Ringwall ships a **step-by-step Setup Wizard** (`ringwallctl setup` and the **Web Setup Wizard** at `http://127.0.0.1:9443`) so **anyone — even non-technical users** — can pick a provider, paste an API key or pick a local model, and run a **live 4-point security & refusal test** before saving:

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
| **Venice.ai API** | Privacy-first cloud | **High** — zero-data-retention API | **None** (runs on any tiny VM/laptop) | Pay-as-you-go / Pro | `venice-uncensored-1-2`, `hermes-3-llama-3.1-405b` |
| **OpenRouter API** | Multi-provider cloud | Depends on route (pick zero-retention) | **None** | Pay-per-token | `cognitivecomputations/dolphin-mistral-24b-venice-edition:free`, `nousresearch/hermes-3-llama-3.1-70b` |
| **Custom OpenAI-Compatible** | Your own vLLM / cloud API | Under your control | Depends on host | Depends on host | Any uncensored OpenAI-compatible model |

- **No YAML editing required:** Run `sudo ringwallctl setup` or use the Web Setup Wizard.
- **API keys stay safe:** Keys are written to separate `0600` files in `/etc/ringwall/keys/` (never inline in `ringwall.yaml` and never returned over the API).
- **Tiered & Consensus Multi-Model Pools:** Combine a fast local abliterated model (Tier 1) with a second local or cloud uncensored model (Tier 2). If a model ever refuses, Ringwall detects it and fails over automatically. If models disagree, **fail-closed strictest verdict wins**.

---

## Architecture

```
  Linux Kernel (eBPF tracepoints: execve, openat, connect)
       │  (automatic unprivileged procfs fallback when CAP_BPF unavailable)
       ▼
  Process Lineage Tracker (/proc + bounded ancestry cache)
       │
       ▼
  Layer 1 — Deterministic Policy Engine (0 ms, YAML rulepacks)
       │   • Core hardening (reverse shells, curl|sh, /etc/shadow, cron/systemd persistence)
       │   • AI-agent guard (SSH/AWS/kube/GPG key access, destructive rm -rf, base64|sh)
       │   • Network egress (C2 ports, raw shell external sockets)
       │
       ├──► IMMEDIATE ENFORCEMENT (before any LLM latency!)
       │    • SIGSTOP freeze / SIGKILL / nftables dynamic IP drop
       │    • Tamper-evident SHA-256 hash-chained audit log
       ▼
  Layer 2 — Multi-Model Uncensored AI Guardian (Ollama / llama.cpp / Venice / OpenRouter)
       │   • Tiered / Failover / Fail-Closed Consensus strategies
       │   • Automatic refusal detector + prompt-injection defense (risk floor >= 90)
       │   • HARD INVARIANT: AI may escalate or explain, NEVER downgrade a hard deny/freeze
       ▼
  Operator Control Plane (127.0.0.1:9443, 0640 bearer token)
       • Guided Web Setup Wizard + Live Monitor (zero external CDN dependencies)
       • CLI (`ringwallctl setup | providers | test-ai | status | simulate | incidents`)
```

---

## Quick Start (Any Linux Host)

```bash
git clone https://github.com/samyxo-bv/ringwall.git
cd ringwall
make build
sudo ./packaging/install.sh

# Run the interactive beginner Setup Wizard (detects RAM/GPU/Ollama & live-tests your model):
sudo ringwallctl setup

# Or compare providers and verify protection anytime:
ringwallctl providers
ringwallctl status
ringwallctl simulate
ringwallctl verify-log
```

Open the local web UI + Setup Wizard at `http://127.0.0.1:9443` (bearer token in `/run/ringwall/api.token`).

---

## Bootable Immutable Hardened ISO

Ringwall ships a reproducible **hybrid BIOS + UEFI bootable Linux appliance ISO** (`iso/build-iso.sh`) built on minimal Debian Bookworm:

- **Read-only SquashFS root filesystem** + ephemeral RAM overlay (reboot wipes all runtime state and persistence attempts).
- **Kernel hardening boot parameters** (`lockdown=integrity`, `init_on_alloc=1`, `init_on_free=1`, `slab_nomerge`, `pti=on`, `randomize_kstack_offset=on`) + strict `sysctl` profile.
- **Default-deny `nftables` firewall** with dynamic `blocked_v4` / `blocked_v6` sets driven by `ringwalld`.
- **Minimal attack surface:** no SSH server, locked `root` password, unprivileged local `operator` console in the `ringwall` group.
- **Optional air-gapped AI model bundle:** pass `--with-model /path/to/model.gguf` to bake an abliterated GGUF directly into the read-only SquashFS.

### Build & Live-Verify the ISO in QEMU

```bash
make build
sudo ./iso/build-iso.sh --out dist/ringwall-appliance-amd64.iso
./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso
```

Every CI run boots the freshly built `.iso` in QEMU and proves live inside the VM that:
1. Rootfs is read-only SquashFS and `sshd` is absent.
2. `ringwalld` runs with the live **eBPF** kernel sensor.
3. A real process attempting to read `~/.ssh/id_ed25519` is caught by eBPF and frozen in kernel state **`T (stopped)`** via `SIGSTOP`.
4. All 5 built-in attack simulations (including prompt-injected `rm -rf /`) are intercepted.
5. The SHA-256 hash-chained audit log passes cryptographic verification.

---

## Security Policy & Threat Model

Read [SECURITY.md](SECURITY.md) for our threat model, explicit non-goals, and vulnerability reporting process.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Built and open-sourced by [Samyxo B.V.](https://github.com/samyxo-bv).
