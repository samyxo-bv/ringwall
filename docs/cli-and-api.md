# CLI & HTTP API Reference

## 1. `ringwalld` Daemon Flags

```bash
ringwalld [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-config` | `/etc/ringwall/ringwall.yaml` | Path to YAML configuration file (falls back to built-in defaults if missing) |
| `-policy-dir` | *(from config)* | Override policy directory path |
| `-mode` | *(from config)* | Override mode (`audit` \| `interactive` \| `strict`) |
| `-sensor` | *(from config)* | Override sensor (`auto` \| `ebpf` \| `procfs` \| `none`) |
| `-listen` | *(from config)* | Override HTTP API listen address |

---

## 2. `ringwallctl` CLI Reference

### Global Flags

```bash
ringwallctl [flags] <command> [args]
```

| Flag | Default | Description |
|---|---|---|
| `-api` | `http://127.0.0.1:9443` | `ringwalld` HTTP API base URL |
| `-token-file` | `/run/ringwall/api.token` | Root-only bearer token file (or set `RINGWALL_TOKEN` env var) |
| `-config` | `/etc/ringwall/ringwall.yaml` | Config file used by `setup` and `test-ai` |
| `-json` | `false` | Print raw JSON responses |

### Local Commands (No Running Daemon Required)

| Command | Description |
|---|---|
| `ringwallctl providers` | Compare local (`Ollama`, `llama.cpp`) and cloud (`Venice.ai`, `OpenRouter`, custom OpenAI-compatible) uncensored AI providers |
| `sudo ringwallctl setup` | Interactive guided Setup Wizard (auto-detects RAM, NVIDIA GPU, local Ollama, runs 4-point refusal test, stores API keys in `0600` files) |
| `sudo ringwallctl test-ai` | Run the live 4-point reachability, zero-refusal, JSON schema, and reverse-shell detection test on configured AI models |
| `ringwallctl policy-check [dir]` | Validate YAML syntax and regexes in all policy files (default `/etc/ringwall/policies.d`) |
| `sudo ringwallctl verify-log [path]` | Verify SHA-256 hash-chain integrity of `/var/log/ringwall/audit.jsonl` (exit `0` valid, exit `2` tampered) |
| `ringwallctl ab-keygen [prefix]` | Generate an Ed25519 A/B signing keypair (`<prefix>.pub` `0644`, `<prefix>.priv` `0600`) |
| `ringwallctl ab-sign <priv> <ver> <url> <file> [out]` | Hash an image file and produce an Ed25519-signed A/B manifest JSON |
| `ringwallctl ab-verify <pub> <manifest> [cur-ver]` | Verify Ed25519 signature, SHA-256 format, and anti-downgrade version constraint |
| `ringwallctl version` | Print `ringwallctl` version |

### Authenticated Daemon Commands (Require Root Token)

| Command | Description |
|---|---|
| `sudo ringwallctl status` | Show version, mode, active eBPF hook (`lsm/file_open`, `fentry`, etc.), LSM blocking state, policy/vpatch counts, drops, incidents, and AI pool |
| `sudo ringwallctl scan` | Trigger an immediate CVE/KEV, stale-library, and kernel drift scan |
| `sudo ringwallctl patch [--dry-run]` | Run a self-healing remediation cycle (drift fixes, security package upgrades, stale service restarts, zero-day virtual patches) |
| `sudo ringwallctl vpatches` | List active TTL-bounded virtual patches and whether kernel LSM exec blocking is active |
| `sudo ringwallctl vpatch-revoke <id>` | Revoke an active virtual patch from `policy.Engine`, kernel `lsm_deny_exec_inodes`, and disk state |
| `sudo ringwallctl ab-status` | Show current A/B slot state (`active_slot`, `last_known_good_slot`, `pending_slot`, `tries_remaining`, `health_confirmed`) |
| `sudo ringwallctl incidents` | List recorded security incidents with severity, status, matched rule, PID, and AI risk score |
| `sudo ringwallctl simulate` | Run 5 safe built-in attack scenarios without affecting host processes |
| `sudo ringwallctl approve <incident-id>` | Resume frozen process and add a strictly scoped `(rule_id, canonical_exe, canonical_path)` exception |
| `sudo ringwallctl resume <incident-id>` | Resume a frozen process once (`SIGCONT` / cgroup thaw) |
| `sudo ringwallctl kill <incident-id>` | Terminate a frozen process (`pidfd`-verified `SIGKILL`) |

---

## 3. Authenticated HTTP REST & SSE API (`127.0.0.1:9443`)

All `/api/v1/*` endpoints require `Authorization: Bearer <token>` using the `0600 root:root` token in `/run/ringwall/api.token`. Missing or invalid tokens return HTTP `401`. The root path `/` serves the self-contained Web UI (zero external CDN requests).

```bash
TOKEN="$(sudo cat /run/ringwall/api.token)"
```

### Status, Telemetry & Audit

| Method & Path | Description |
|---|---|
| `GET /api/v1/status` | Daemon status snapshot (`DaemonStatus` JSON) |
| `GET /api/v1/events` | Server-Sent Events (`text/event-stream`) streaming live `incident` events |
| `GET /api/v1/incidents` | List all recorded incidents |
| `POST /api/v1/incidents/{id}/action` | Operator decision: `{"action": "approve" \| "resume" \| "kill"}` |
| `POST /api/v1/simulate` | Run the 5 built-in safe attack simulations |
| `GET /api/v1/audit/verify` | Verify SHA-256 hash-chain integrity of `audit.jsonl` (`{"valid": true, "entries": N}`) |

### Guided Setup Wizard API

| Method & Path | Description |
|---|---|
| `GET /api/v1/setup/info` | Provider catalog, environment detection (RAM/GPU/Ollama), and redacted active model summary |
| `POST /api/v1/setup/test-model` | Run the live 4-point reachability + refusal test against a candidate model |
| `POST /api/v1/setup/apply` | Save updated `ringwall.yaml` + `0600` API key files and live-reload daemon config |

### Scanner, Patcher, Virtual Patches & A/B Updates

| Method & Path | Description |
|---|---|
| `GET /api/v1/scan` | **Read-only:** return the last cached `ScanReport` (or `{"scanned": false}` if none yet) |
| `POST /api/v1/scan` | Execute a live CVE/KEV, stale-library, and drift scan (and run fail-closed virtual-patch `Reconcile` + `RefreshAndSync`) |
| `POST /api/v1/patch` | Execute a self-healing patch cycle; optional body `{"dry_run": true}` |
| `GET /api/v1/virtual-patches` | List active TTL-bounded virtual patches |
| `POST /api/v1/virtual-patches` | Install an operator virtual patch (validated against live-inode anti-lockout rules) |
| `DELETE /api/v1/virtual-patches/{id}` | Revoke a virtual patch and clear its inode from `lsm_deny_exec_inodes` |
| `GET /api/v1/ab/status` | Return current `ABSlotState` |
| `POST /api/v1/ab/stage` | Verify an Ed25519-signed `ABManifest` and stage the image to the inactive slot (requires `patcher.ab_update.enabled: true`) |

### `curl` Examples

Install and later revoke an emergency zero-day virtual patch blocking execution of `/usr/local/bin/vuln-tool`:

```bash
TOKEN="$(sudo cat /run/ringwall/api.token)"

curl -fsS -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "VP-CVE-2026-99999",
    "cve": "CVE-2026-99999",
    "package": "vuln-tool",
    "target_exe_paths": ["/usr/local/bin/vuln-tool"],
    "action": "freeze",
    "source": "operator",
    "rationale": "Temporary containment pending upstream security release"
  }' \
  http://127.0.0.1:9443/api/v1/virtual-patches

# Revoke once upstream fix is installed:
curl -fsS -X DELETE \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9443/api/v1/virtual-patches/VP-CVE-2026-99999
```

Read non-sensitive health status as an unprivileged user (no API token required):

```bash
cat /run/ringwall-status/status.json
```
