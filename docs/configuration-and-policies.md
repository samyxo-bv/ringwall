# Configuration & Policy Reference

## 1. Main Configuration (`/etc/ringwall/ringwall.yaml`)

Ringwall loads `/etc/ringwall/ringwall.yaml` (`0600 root:root`) by default. Override with `ringwalld -config /path/to/ringwall.yaml`.

### Top-Level Fields

| Key | Default | Values / Description |
|---|---|---|
| `mode` | `interactive` | `audit` (observe/log only, LSM blocking disabled), `interactive` (synchronous LSM `-EPERM` + `SIGSTOP` freeze pending operator approval), `strict` (synchronous LSM `-EPERM` + immediate `SIGKILL` on `kill` rules) |
| `policy_dirs` | `["/etc/ringwall/policies.d"]` | Directories of static YAML policy packs loaded at startup (keep `patcher.virtual_patch_file` outside these directories) |
| `audit_log_path` | `/var/log/ringwall/audit.jsonl` | SHA-256 hash-chained audit trail (`0600 root:root`) |

### `sensor`

| Key | Default | Description |
|---|---|---|
| `mode` | `auto` | `auto` (eBPF LSM → fentry → tracepoints → procfs), `ebpf`, `procfs`, or `none` |
| `bpf_object_path` | `/usr/lib/ringwall/ringwall.bpf.o` | Fallback path when `ringwalld` is built without `-tags ebpf_embed` |
| `poll_interval_ms` | `250` | Poll interval for `procfs` fallback sensor |
| `enable_lsm_blocking` | `true` | Enables synchronous `-EPERM` enforcement when `lsm/file_open` is attached (automatically forced off in `audit` mode) |
| `lsm_allowed_ssh_exes` | `[]` | Exact canonical executable paths exempted from SSH private-key LSM blocking. Empty by default (zero exemptions). |

### `scanner`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable periodic host CVE, CISA KEV, stale-library, and drift scans |
| `interval_min` | `60` | Background scan interval in minutes |
| `allow_online_feeds` | `false` | Opt-in HTTPS queries to OSV.dev (`api.osv.dev`) and CISA KEV (`cisa.gov`). Must be HTTPS; loopback/private URLs are rejected unless using an offline bundle. |
| `osv_base_url` | `https://api.osv.dev` | Custom HTTPS OSV-compatible endpoint |
| `cisa_kev_url` | CISA official JSON feed | Custom HTTPS KEV feed URL |
| `offline_db_path` | `""` | Path to local airgapped JSON advisory bundle (see [Self-Healing Guide](self-healing-and-ab-updates.md)) |

### `patcher`

| Key | Default | Description |
|---|---|---|
| `mode` | `virtual_only` | `off` (scan only), `virtual_only` (virtual patches for unpatched 0-days + drift fixes; no `apt-get`), `auto_critical` (auto-patch KEV/Critical CVEs with upstream fix + 0-day virtual patches + drift), `auto_all` (auto-patch all CVEs with upstream fix + virtual patches + drift) |
| `dry_run` | `false` | Compute and log patch plans without modifying packages, sysctls, or virtual patches |
| `auto_fix_drift` | `true` | Automatically restore allowlisted baseline sysctls and `0600` token/audit permissions |
| `restart_stale_services` | `true` | Restart non-protected systemd units holding deleted `.so` libraries after upgrades |
| `ai_virtual_patch` | `true` | Allow uncensored AI Guardian to propose declarative virtual patches (always validated against hard anti-lockout rules; deterministic fallback if AI disabled/unavailable) |
| `virtual_patch_file` | `/var/lib/ringwall/virtual-patches.json` | Persisted `0600` JSON store for active TTL-bounded virtual patches (must stay outside `policy_dirs`) |
| `ab_update.enabled` | `false` | Opt-in Ed25519 A/B slot staging & boot-health confirmation (experimental for disk-installed GRUB/systemd-boot appliances) |
| `ab_update.trusted_pubkey_ed25519_b64` | `""` | Base64-encoded Ed25519 public key verifying A/B manifests (official Ringwall key: [`packaging/ringwall-release.pub`](../packaging/ringwall-release.pub)) |
| `ab_update.state_path` | `/var/lib/ringwall/ab-state.json` | Atomic A/B slot state and boot-counter file (`0600`) |
| `ab_update.boot_env_path` | `/var/lib/ringwall/ab-boot.env` | Bootloader slot selector env file (`RINGWALL_BOOT_SLOT=A\|B`, `RINGWALL_BOOT_TRIES=<n>`) |
| `ab_update.slot_a_path` / `slot_b_path` | `/var/lib/ringwall/slot_a.squashfs` / `slot_b.squashfs` | Inactive slot staging image paths |

### `enforcer`

| Key | Default | Description |
|---|---|---|
| `enable_signals` | `true` | Enable `pidfd`-verified `SIGSTOP` / `SIGKILL` |
| `enable_nftables` | `false` | Enable dynamic `nftables` `blocked_v4` / `blocked_v6` updates (`true` inside the Ringwall ISO) |
| `nft_table` | `inet ringwall` | Target `nftables` family + table name (`^[a-zA-Z0-9_]+ [a-zA-Z0-9_]+$`) |
| `dry_run` | `false` | Log enforcement actions without signaling processes or updating `nftables` |

### `ai`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable asynchronous AI Guardian triage (never blocks or weakens deterministic rules) |
| `strategy` | `tiered` | `tiered`, `consensus`, or `failover` |
| `escalate_threshold` | `55` | Risk score (`0-100`) at which `tiered` invokes Tier 2 |
| `allow_remote_endpoint` | `false` | Global opt-in for non-loopback HTTPS AI endpoints (can also be set per model) |
| `models[]` | Ollama local Tier 1 | List of model entries: `name`, `provider` (`ollama`\|`openai`\|`venice`\|`openrouter`), `endpoint`, `model`, `tier` (`1`\|`2`), `abliterated`, `allow_remote_endpoint`, `api_key_env` or `api_key_file` (`0600`), `timeout_sec` |

### `api`

| Key | Default | Description |
|---|---|---|
| `listen_addr` | `127.0.0.1:9443` | Loopback admin HTTP API & Web UI listen address |
| `token_file` | `/run/ringwall/api.token` | Root-only (`0600`) bearer token file |
| `allow_non_loopback` | `false` | Must explicitly be `true` to bind outside loopback (not recommended without a reverse proxy / mTLS) |

---

## 2. Built-In Deterministic Policy Rules (13 Rules)

### Core Host Hardening (`policies/00-core-hardening.yaml`)

| Rule ID | Severity | Default Action | MITRE | What it detects |
|---|---|---|---|---|
| `RW-CORE-001` | critical | `kill` | T1059.004 | Reverse shells (`/dev/tcp`, `/dev/udp`, `nc -e/-c/--sh-exec`, `socat exec:`, Python socket + `subprocess`/`pty.spawn`) |
| `RW-CORE-002` | high | `freeze` | T1059.004 | Pipe-to-shell RCE (`curl`/`wget ... \| sh`/`bash`) |
| `RW-CORE-003` | critical | `freeze` | T1003.008 | Non-auth binaries reading `/etc/shadow` or `/etc/gshadow` |
| `RW-CORE-004` | critical | `freeze` | T1053.003 | Unauthorized writes to `/etc/cron*`, `/var/spool/cron/**`, or `/etc/systemd/system/**` |
| `RW-CORE-005` | high | `freeze` | T1098.004 | Writes, renames, hardlinks, or symlinks into `**/.ssh/authorized_keys*` |
| `RW-CORE-006` | critical | `freeze` | T1547.006 | `insmod` / `modprobe` outside `systemd-udevd` |
| `RW-CORE-007` | critical | `freeze` | T1055 | `io_uring_setup` invocations (prevents async syscall-bypass evasion on kernels < 6.6) |

### AI Coding & Autonomous Agent Guard (`policies/10-ai-agent-guard.yaml`)

| Rule ID | Severity | Default Action | MITRE | What it detects |
|---|---|---|---|---|
| `RW-AGENT-001` | critical | `freeze` | T1552.004 | Any process opening SSH private keys (`**/.ssh/id_*`, `*.pem`, `*.key`, excluding `*.pub`; zero default `exclude_exe_paths`) |
| `RW-AGENT-002` | critical | `freeze` | T1552.001 | Agent process trees (`claude`, `codex`, `cursor`, `openclaw`, `copilot`, `aider`, `mcp`, `agent`) reading `.aws/credentials`, `.kube/config`, `.docker/config.json`, `.gnupg/private-keys-v1.d/**`, or `.config/gcloud/credentials.db` |
| `RW-AGENT-003` | critical | `kill` | T1485 | Destructive recursive `rm` targeting `/`, `/etc`, `/usr`, `/var`, `/home`, `/root`, or `~` (handles GNU `--r`/`--rec`, relative targets via `Cwd`, `cd / && rm -r usr`) |
| `RW-AGENT-004` | high | `freeze` | T1027 | Encoded payload execution (`base64 -d \| sh/bash/python/perl/ruby`) |

### Network Egress (`policies/20-network-egress.yaml`)

| Rule ID | Severity | Default Action | MITRE | What it detects |
|---|---|---|---|---|
| `RW-NET-001` | critical | `block_egress` | T1571 | Public outbound connections to common reverse-shell/C2 ports (`4444`, `1337`, `31337`, `9001`, `5555`) |
| `RW-NET-002` | high | `block_egress` | T1071 | Raw shells or netcat/socat initiating public outbound connections |

---

## 3. Built-In Baseline Hardening & Drift Checks (`RW-DRIFT-001..011`)

| Drift ID | Severity | Target | Expected |
|---|---|---|---|
| `RW-DRIFT-001` | medium | `kernel.kptr_restrict` | `2` |
| `RW-DRIFT-002` | low | `kernel.dmesg_restrict` | `1` |
| `RW-DRIFT-003` | high | `kernel.unprivileged_bpf_disabled` | `1` (or `2`) |
| `RW-DRIFT-004` | high | `kernel.unprivileged_userns_clone` (optional) | `0` |
| `RW-DRIFT-005` | high | `kernel.yama.ptrace_scope` (optional) | `2` |
| `RW-DRIFT-006` | high | `kernel.io_uring_disabled` (optional, Linux 6.6+) | `2` |
| `RW-DRIFT-007` | medium | `fs.protected_hardlinks` | `1` |
| `RW-DRIFT-008` | medium | `fs.protected_symlinks` | `1` |
| `RW-DRIFT-009` | medium | `fs.suid_dumpable` | `0` |
| `RW-DRIFT-010` | critical | `api.token_file` permissions | `0600` |
| `RW-DRIFT-011` | critical | `audit_log_path` permissions | `0600` |

---

## 4. Writing Custom YAML Policies

Drop additional `.yaml` files into `/etc/ringwall/policies.d/` and validate them with `ringwallctl policy-check /etc/ringwall/policies.d`.

Supported `match` fields (`internal/policy/engine.go`):
- `event_types`: list of `exec`, `open`, `connect`, `io_uring`
- `comm_in`: list of process short names (`comm`)
- `exe_paths` / `exclude_exe_paths`: exact canonical full executable paths (immune to `comm` spoofing)
- `path_globs` / `exclude_path_globs`: glob patterns supporting `*` and `**`
- `cmdline_regex`: Go RE2 regular expressions matched against kernel `argv` (and `/proc/<pid>/cmdline` as additive OR)
- `destructive_rm`: `true` enables tokenized destructive `rm` detection
- `ancestor_any`: matches if any process in the parent ancestry has a matching `comm`
- `require_write`: `true` requires `O_WRONLY | O_RDWR | O_CREAT | O_TRUNC` (or link/rename destination)
- `dst_ports`: list of destination TCP/UDP ports
- `dst_ip_not_private`: `true` skips loopback, RFC1918, link-local, and ULA destinations

Example custom rule protecting a production `.env` file from non-application processes:

```yaml
rules:
  - id: RW-CUSTOM-001
    name: Unauthorized read of production secrets
    category: custom
    severity: critical
    action: freeze
    description: Freezes any process other than the app binary opening /srv/myapp/.env.
    match:
      event_types: [open]
      path_globs:
        - '/srv/myapp/.env'
      exclude_exe_paths:
        - '/usr/local/bin/myapp'
```

Validate and apply:

```bash
ringwallctl policy-check /etc/ringwall/policies.d
sudo systemctl restart ringwalld
```
