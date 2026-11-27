# CVE/KEV Scanner, Self-Healing Patcher, Zero-Day Virtual Patching & Signed A/B Updates

Ringwall does **not** claim an AI can magically discover and safely live-patch unknown zero-day C/Go source code in production. Instead, it automates the full deterministic remediation lifecycle across four well-defined lanes:

| Lane | Condition | Automated Action |
|---|---|---|
| `immediate_patch` | Upstream fix exists **AND** (CISA KEV or exposed Critical) | Security-only `apt-get install --only-upgrade` + restart non-protected stale services (`auto_critical` / `auto_all`) |
| `virtual_patch` | **No upstream fix yet** (active 0-day / unpatched KEV or Critical/High) | Synthesize TTL-bounded declarative containment rule + synchronous `lsm/bprm_check_security` exec blocking under hard anti-lockout guardrails |
| `scheduled_patch` | Upstream fix exists, lower urgency | Patched automatically in `auto_all` mode (or reported for planned maintenance in `auto_critical` / `virtual_only`) |
| `drift_fix` | Kernel sysctl or `0600` file-permission regression (`RW-DRIFT-001..011`) | Restores allowlisted baseline sysctls and `0600` permissions when `patcher.auto_fix_drift: true` |

---

## 1. Continuous Deterministic Scanner (`internal/scanner`)

Every scan (`sudo ringwallctl scan`, `POST /api/v1/scan`, or the background `scanner.interval_min` loop) inspects:
1. **Local package inventory:** Pure-Go parsers for Debian/Ubuntu (`/var/lib/dpkg/status`) and Alpine (`/lib/apk/db/installed`) — no external subprocesses.
2. **Stale running processes (`needrestart`-equivalent):** Walks `/proc/*/maps` to find processes still mapping `(deleted)` binaries or `.so` shared libraries after upgrades, mapping PIDs back to their systemd units.
3. **Kernel & file-permission drift:** Verifies `RW-DRIFT-001..011` (baseline sysctls + `0600` permissions on `api.token` and `audit.jsonl`).
4. **Vulnerability correlation:**
   - **Online opt-in (`scanner.allow_online_feeds: true`):** Batches packages against HTTPS **OSV.dev** (`/v1/querybatch` + deterministic sorted `/v1/vulns/<id>` detail fetches) and overlays **CISA KEV** (including `knownRansomwareCampaignUse`). Marks `truncated=true` if OSV returns `next_page_token`, short results, >150 unique IDs, or any detail error.
   - **Airgapped offline bundle (`scanner.offline_db_path`):** Works 100% offline with zero internet access.

### Offline Advisory Bundle Format (`scanner.offline_db_path`)

```json
{
  "updated_at": "2026-11-27T08:00:00Z",
  "advisories": [
    {
      "id": "CVE-2026-50001",
      "cve": "CVE-2026-50001",
      "package": "openssl",
      "ecosystem": "Debian",
      "fixed_version": "3.0.11-1~deb12u2",
      "severity": "critical",
      "in_kev": true,
      "summary": "Fixable KEV vulnerability in OpenSSL"
    },
    {
      "id": "CVE-2026-50002",
      "cve": "CVE-2026-50002",
      "package": "vuln-agent-tool",
      "fixed_version": "",
      "severity": "critical",
      "in_kev": true,
      "summary": "Unpatched zero-day RCE (no upstream fix yet)",
      "affected_bins": ["/usr/bin/vuln-agent-tool"]
    }
  ]
}
```

Leaving `fixed_version` empty (`""`) routes the finding to `virtual_patch` (unpatched zero-day containment).

---

## 2. Host Auto-Patcher (`internal/patcher/host_patcher.go`)

Choose your automation level in `/etc/ringwall/ringwall.yaml`:
- `patcher.mode: off` — scan only; `RunPatchCycle` skips all modifications.
- `patcher.mode: virtual_only` *(default)* — installs TTL-bounded virtual patches for unpatched 0-days and fixes baseline drift; never runs `apt-get`.
- `patcher.mode: auto_critical` — upgrades `immediate_patch` (KEV / exposed Critical) packages + fixes drift + virtual-patches unpatched 0-days.
- `patcher.mode: auto_all` — upgrades all fixable CVEs + fixes drift + virtual-patches unpatched 0-days.

Safety guarantees:
- **Zero shell execution:** `apt-get` and `systemctl` run via direct `exec.CommandContext` argv arrays with strict package-name regex validation (`^[a-z0-9][a-z0-9+.-]{0,127}$`).
- **Protected units are never restarted automatically:** `ringwalld.service`, `sshd.service`, `ssh.service`, `dbus.service`, `dbus-broker.service`, `systemd-*`, and `user@*.service` are skipped (`skipped_protected`) so automated patching never drops your management session.
- **Immediate post-upgrade inode refresh:** Right after `PatchPackages` succeeds, `daemon.RunPatchCycle` invokes `vpMgr.RefreshAndSync()` so upgraded system binaries refresh their live `(dev, ino)` anti-lockout index and clear any obsolete `lsm_deny_exec_inodes` entries.

Preview a patch cycle safely at any time:

```bash
sudo ringwallctl patch --dry-run
```

---

## 3. Zero-Day Virtual Patcher & Hard Anti-Lockout Invariants

When a Critical/High/KEV CVE has **no upstream fix yet**, Ringwall creates a temporary, declarative **Virtual Patch** (optionally proposed by the uncensored AI Guardian when `patcher.ai_virtual_patch: true`, falling back to offline deterministic synthesis).

### Hard Anti-Lockout Guardrails (`internal/patcher/virtual_patch.go`)

Every virtual patch — whether deterministic, AI-assisted, or operator-submitted — must pass all of these checks before activation and again on every restart/sync:
1. **No raw code or shell:** Virtual patches are strictly declarative Ringwall policy rules (`target_exe_paths`, `target_path_globs`, `target_ports`) with mandatory TTL (`default 72h`, `max 168h`).
2. **AI action cap:** `ai_assisted` patches may only use `freeze` or `block_egress` — **never `kill`**.
3. **Live `(dev, ino)` protected binary index:** Built from canonical paths, usrmerge aliases (`/bin/` ↔ `/usr/bin/`, `/sbin/` ↔ `/usr/sbin/`), `/etc/shells`, and dynamic globs (`/lib/systemd/systemd*`, `/usr/lib/systemd/systemd*`, `/usr/lib/openssh/*`, `/usr/libexec/openssh/*`). Protects `ringwalld`, `ringwallctl`, `init`, `systemd*`, `dbus*`, `sshd`, `sshd-session`, `sshd-auth`, `login`, `agetty`, `sudo`, `su`, `passwd`, `sh`/`bash`/`rbash`/`dash`/`zsh`, `apt`/`apt-get`/`dpkg`, `systemctl`, `reboot`, `shutdown`.
4. **Symlink & TOCTOU rejection:** `ValidateVirtualPatch` rejects symlinks via `os.Lstat`; `collectBlockedExecPathsLocked` re-validates live regular files and inodes on every sync; `ebpfSensor.SyncBlockedExecPaths` opens each target via `O_PATH|O_NOFOLLOW`, verifies `S_IFREG` (never blocking on FIFOs/devices), reads `FS_IOC_GETVERSION` (`inode->i_generation` on `ext4`/`xfs`/`btrfs`), and re-stats protected binaries live on every sync.
5. **Strict glob & port validation:** Rejects `**`, `..`, fewer than 3 fixed leading path components before wildcards, critical prefixes (`/root`, `/boot`, `/etc/ssh`, `/etc/pam*`, `/etc/sudoers*`, `/etc/systemd`, `/etc/ringwall`, `/etc/passwd`, `/etc/shadow`, `/etc/profile*`, `/etc/ld.so*`, `/proc`, `/sys`, `/dev`, etc.), `.ssh` segments, login/shell dotfiles (`.profile`, `.bashrc`, `authorized_keys`, user dotfiles under `/home`), port `0`, and automated blocking of ports `22`, `53`, `80`, `443`, `9443`.
6. **Runtime `vpExeGuard` in `policy.Engine`:** Even if an operator creates a custom glob or port virtual patch, `policy.Engine.Evaluate` checks `vpExeGuard` (outside `RLock`, after a virtual rule matches) and **never** matches, freezes, or kills any protected system binary.
7. **Persisted outside `policy_dirs` & fail-closed `Reconcile`:** Active patches persist atomically (`CreateTemp` + `0600` + `fsync` + `rename`) in `/var/lib/ringwall/virtual-patches.json`, preserving TTLs, `DELETE` revocation, UI visibility, and `lsm_deny_exec_inodes` across restarts. `Reconcile` **never** auto-revokes an unexpired CVE patch when a scan has feed errors, `Complete=false`, `Truncated=true` (including OSV pagination), or `PackageCount == 0`.

---

## 4. Signed Ed25519 A/B Immutable Updates (Experimental for Disk-Installed Appliances)

> **Honest scope note:** The bootable live ISO runs from read-only SquashFS on `ringwall.slot=A` (where `ab-keygen`/`ab-sign`/`ab-verify` work live). Full two-partition A/B switching and boot-counter rollback is **experimental** and requires a disk-installed bootloader (GRUB or `systemd-boot`) configured to source `/var/lib/ringwall/ab-boot.env` and pass `ringwall.slot=A` or `ringwall.slot=B` on the kernel command line.

### Generating Keys, Signing & Verifying Releases

```bash
# 1. Generate an offline Ed25519 release signing keypair:
ringwallctl ab-keygen ringwall-release
# -> ringwall-release.pub (0644) and ringwall-release.priv (0600)

# 2. Sign a release image into an A/B manifest:
ringwallctl ab-sign ringwall-release.priv \
  v0.2.0 \
  https://github.com/samyxo-bv/ringwall/releases/download/v0.2.0/ringwall-v0.2.0-appliance-amd64.iso \
  dist/ringwall-appliance-amd64.iso \
  ringwall-v0.2.0-ab-manifest.json

# 3. Verify signature & anti-downgrade monotonicity against current version:
ringwallctl ab-verify ringwall-release.pub ringwall-v0.2.0-ab-manifest.json v0.1.0
```

### Boot-Confirmed Promotion & Automatic Rollback

When `patcher.ab_update.enabled: true` and a verified manifest is staged via `POST /api/v1/ab/stage`:
1. `ABUpdater` verifies the Ed25519 signature, anti-downgrade (`version > current` and `current >= min_version`), HTTPS URL + redirect validation, exact SHA-256 digest, and exact byte size before writing to the inactive slot (`O_EXCL` symlink-safe temp file + `fsync` + atomic rename).
2. `ABUpdater` sets `pending_slot` with `tries_remaining: 2` in `/var/lib/ringwall/ab-state.json` and writes `RINGWALL_NEXT_SLOT=B` into `/var/lib/ringwall/ab-boot.env`.
3. On subsequent `ringwalld` startups, `ConfirmBootHealth` reads `/proc/cmdline` for `ringwall.slot=A|B`:
   - If the kernel is **still booted on the old slot** (e.g. a normal daemon restart without rebooting), `ConfirmBootHealth` is a strict no-op — it never falsely promotes an unbooted slot.
   - Once the kernel actually boots `ringwall.slot=B` and `ringwalld` starts healthy (sensor active + policies loaded), slot `B` is promoted to `active_slot` and `last_known_good_slot`.
   - If the new slot fails startup health checks twice (`tries_remaining` reaches `0`), `ABUpdater` automatically flips `ab-boot.env` back to `last_known_good_slot`.
