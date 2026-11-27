# Ringwall

**Deterministic Linux runtime guardian (eBPF tracepoints + process-lineage policy engine) with a refusal-resistant, uncensored AI Guardian — beginner-friendly guided setup, installable on any Linux host, and shipped as an automated, immutable bootable ISO.**

> **Security honesty upfront:** No operating system has "zero security issues", and an LLM must **never** be your primary security boundary. Ringwall enforces **deterministically at kernel/OS speed first** (`eBPF` + `pidfd` `SIGSTOP`/`SIGKILL` + optional cgroup v2 freezer & `nftables`), and layers an **uncensored / abliterated AI Guardian** on top to explain incidents in plain language, analyze obfuscated attacks, and escalate ambiguous threats. **The AI can never downgrade a deterministic block or freeze.**

---

## Why an Uncensored (Abliterated) AI Model?

Standard cloud AI models (like default ChatGPT or Claude) are often **unsuitable as cybersecurity daemons** because their safety filters trigger on real threat logs. Feed them a reverse shell (`bash -i >& /dev/tcp/...`) or an obfuscated exploit payload and they reply *"I cannot assist with malware"* — leaving your defense blind right when an attack happens.

An **abliterated / uncensored model** has those false-positive refusals removed so it inspects defensive security telemetry honestly, classifies real threats, and explains them clearly in human language.

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

- **No YAML editing required:** Run `sudo ringwallctl setup` or use the Web Setup Wizard.
- **Root-only control plane & `0600` secret storage:** `/run/ringwall/api.token`, `/var/log/ringwall/audit.jsonl`, and `/etc/ringwall/keys/*.key` are strictly `0600 root:root` — monitored unprivileged users cannot read or tamper with them.
- **Tiered & Consensus Multi-Model Pools:** Combine a fast local abliterated model (Tier 1) with a second local or cloud uncensored model (Tier 2). If a model ever refuses, Ringwall detects it and fails over automatically. If models disagree, **fail-closed strictest verdict wins**.

---

## Architecture

```
  Linux Kernel (eBPF tracepoints: execve, execveat, openat, openat2, open, connect, sendto)
       │  • 4 MiB ringbuf + per-CPU drop counter (raises RW-SYS-DROP incident if drops occur)
       │  • Automatic unprivileged procfs fallback when CAP_BPF is unavailable
       ▼
  Process Lineage & Canonical Path Resolver
       │  • Resolves cwd, dirfd, /proc/self/root, symlinks, and double slashes
       │  • Captures process StartTime for PID-reuse-safe signaling
       ▼
  Layer 1 — Deterministic Policy Engine (0 ms, YAML rulepacks)
       │  • Core hardening (/etc/shadow, cron/systemd persistence, reverse shells, kernel modules)
       │  • AI-agent guard (SSH/AWS/kube/GPG key access, tokenized destructive rm parser, encoded exec)
       │  • Exact canonical exclude_exe_paths (cannot be spoofed via /tmp/ssh or PR_SET_NAME)
       │
       ├──► IMMEDIATE ENFORCEMENT (before any LLM latency!)
       │    • pidfd_send_signal (SIGSTOP/SIGKILL) + agent-ancestor freeze + cgroup v2 freezer
       │    • Tamper-evident SHA-256 hash-chained audit log (0600 root)
       ▼
  Layer 2 — Bounded Multi-Model Uncensored AI Guardian (Ollama / llama.cpp / Venice / OpenRouter)
       │  • Secret-redacted telemetry, prompt-injection defense, automatic refusal failover
       │  • HARD INVARIANT: AI may escalate or explain, NEVER downgrade a hard deny/freeze
       ▼
  Root-Only Admin Control Plane (127.0.0.1:9443, 0600 bearer token)
       • Guided Web Setup Wizard + Live Monitor (zero external CDN dependencies)
       • CLI (`sudo ringwallctl setup | providers | test-ai | status | simulate | incidents`)
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
sudo ringwallctl status
sudo ringwallctl simulate
sudo ringwallctl verify-log
```

Open the local web UI + Setup Wizard at `http://127.0.0.1:9443` using the root-only bearer token from `sudo cat /run/ringwall/api.token`.

---

## Bootable Immutable Hardened ISO

Ringwall ships an automated **hybrid BIOS + UEFI bootable Linux appliance ISO** (`iso/build-iso.sh`) built on minimal Debian Bookworm (pin `DEBIAN_MIRROR` to a `snapshot.debian.org` URL + `SOURCE_DATE_EPOCH` for pinned builds):

- **Read-only SquashFS root filesystem** + ephemeral RAM overlay (reboot wipes all runtime state and persistence attempts).
- **Kernel hardening boot parameters** (`lockdown=integrity`, `init_on_alloc=1`, `init_on_free=1`, `slab_nomerge`, `pti=on`, `randomize_kstack_offset=on`) + strict `sysctl` profile (`kernel.io_uring_disabled = 2` on kernels 6.6+, plus live eBPF `io_uring_setup` freeze on kernel 6.1+).
- **Default-deny `nftables` firewall** with dynamic `blocked_v4` / `blocked_v6` sets driven by `ringwalld`.
- **Strict privilege isolation:** no SSH server, locked `root` and `operator` passwords, monitored `operator` user has zero access to `/run/ringwall/api.token` (`0600 root`) or `/var/log/ringwall/audit.jsonl`.
- **Optional air-gapped AI model bundle:** pass `--with-model /path/to/model.gguf` to bake an abliterated GGUF directly into the read-only SquashFS.

### Build & Live-Verify the ISO in QEMU

```bash
make build
sudo ./iso/build-iso.sh --out dist/ringwall-appliance-amd64.iso
./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso
```

Every CI run boots the freshly built `.iso` in QEMU as the unprivileged monitored user and proves live inside the VM that:
1. Rootfs is read-only SquashFS and `sshd` is absent.
2. Monitored user `operator` **cannot** read `/run/ringwall/api.token` or `/var/log/ringwall/audit.jsonl` and gets HTTP `401` from the control API.
3. `ringwalld` runs with the live **eBPF** kernel sensor and `0` dropped events.
4. Calling `io_uring_setup` (syscall 425) is caught by eBPF and frozen in kernel state **`T (stopped)`**.
5. Direct `~/.ssh/id_ed25519` read, `//home` double-slash bypass, `/proc/self/cwd` bypass, and `/tmp/d/id_ed25519` directory-symlink bypass (across `PrivateTmp=yes`) are all canonicalized and frozen in **`T (stopped)`**.
6. Live `execve` attacks (`bash -c` reverse-shell pattern and `rm -r /usr` without `-f`) are caught and frozen in **`T (stopped)`**.

---

## Security Policy & Threat Model

Read [SECURITY.md](SECURITY.md) for our honest threat model, explicit non-goals, async tracepoint boundaries, and vulnerability reporting process.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Built and open-sourced by [Samyxo B.V.](https://github.com/samyxo-bv).
