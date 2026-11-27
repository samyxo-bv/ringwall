# Getting Started with Ringwall

This guide walks you through installing Ringwall on a Linux host or booting the verified immutable ISO, enabling synchronous eBPF LSM kernel blocking, configuring an uncensored/local AI Guardian, and verifying protection end-to-end.

---

## Choose Your Installation Path

| Path | Best for | What you get |
|---|---|---|
| **1. Prebuilt Linux release tarball** | Fastest setup on Debian/Ubuntu/Linux servers & workstations | Static `ringwalld` + `ringwallctl` (with embedded eBPF bytecode), policies, systemd unit, sysctl profile, `nftables.conf` |
| **2. Build from source** | Custom policies, auditing the build, or non-x86_64 builds | Compiled directly from `ebpf/ringwall.bpf.c` + Go 1.25+ source |
| **3. Bootable Immutable ISO (`194 MB`)** | Airgapped bastion, AI-agent sandbox VM, or live security appliance | Read-only Debian Bookworm SquashFS with `lsm=lockdown,yama,integrity,apparmor,bpf` pre-enabled |

---

## Option 1: Install from the Prebuilt Release Tarball (Recommended)

Download the latest release (`v0.2.0`) and verify its SHA-256 checksum first:

```bash
VERSION=v0.2.0
BASE="https://github.com/samyxo-bv/ringwall/releases/download/${VERSION}"

curl -fsSLO "${BASE}/ringwall-${VERSION}-linux-amd64.tar.gz"
curl -fsSLO "${BASE}/SHA256SUMS.txt"
grep "linux-amd64.tar.gz" SHA256SUMS.txt | sha256sum -c -

mkdir -p ringwall-install
tar -xzf "ringwall-${VERSION}-linux-amd64.tar.gz" -C ringwall-install
cd ringwall-install
sudo ./packaging/install.sh
```

What `packaging/install.sh` installs:
- `/usr/local/bin/ringwalld` and `/usr/local/bin/ringwallctl` (`0755`)
- `/usr/lib/ringwall/ringwall.bpf.o` (`0644`, plus embedded directly inside `ringwalld`)
- `/etc/ringwall/ringwall.yaml` (`0600 root:root`, never overwrites an existing file)
- `/etc/ringwall/policies.d/*.yaml` (`0644`)
- `/etc/sysctl.d/99-ringwall.conf` (`0644`) and applies `sysctl --system`
- `/etc/systemd/system/ringwalld.service` (`0644`) and runs `systemctl enable --now ringwalld.service`
- Root-only directories (`0700`): `/etc/ringwall/keys`, `/var/log/ringwall`, `/run/ringwall`

---

## Option 2: Build from Source

### Prerequisites (Debian / Ubuntu)
- Go `1.25+` (CI builds and tests with Go `1.27`)
- `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`, `make`

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev make

git clone https://github.com/samyxo-bv/ringwall.git
cd ringwall

# Compile eBPF object + static Go binaries with embedded eBPF bytecode:
make build

# Optional: run full Go vet + race test suite:
make vet && make test

# Install and start systemd service:
sudo ./packaging/install.sh
```

---

## Option 3: Boot the Immutable Appliance ISO in QEMU or on Hardware

```bash
VERSION=v0.2.0
BASE="https://github.com/samyxo-bv/ringwall/releases/download/${VERSION}"

curl -fsSLO "${BASE}/ringwall-${VERSION}-appliance-amd64.iso"
curl -fsSLO "${BASE}/SHA256SUMS.txt"
grep "appliance-amd64.iso" SHA256SUMS.txt | sha256sum -c -

# Boot headless in QEMU (add -enable-kvm -cpu host on Linux hosts with KVM):
qemu-system-x86_64 -m 1536 -smp 2 -nographic -cdrom "ringwall-${VERSION}-appliance-amd64.iso" -boot d
```

See [Immutable ISO Guide](immutable-iso.md) for building your own ISO, embedding a local GGUF model (`--with-model`), and running all 16 live QEMU attack assertions.

---

## Enable Synchronous eBPF LSM Blocking on Standard Linux Hosts

Check whether your host kernel currently has the `bpf` LSM active:

```bash
cat /sys/kernel/security/lsm
```

- If the output contains **`bpf`** (for example `lockdown,capability,yama,apparmor,bpf`): Ringwall automatically activates **Tier 1 synchronous `-EPERM` kernel blocking** (`open_hook=lsm/file_open lsm_blocking=true`).
- If `bpf` is **not** listed: Ringwall still works via **Tier 2** (`fentry/security_file_open` with `bpf_d_path`, asynchronous `SIGSTOP`), and you can enable BPF LSM on Debian/Ubuntu by editing `/etc/default/grub`:

```bash
# Append ",bpf" to the existing LSM list (keep your current LSMs such as lockdown,yama,apparmor):
# Example:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet lsm=lockdown,yama,integrity,apparmor,bpf"

sudo update-grub
sudo reboot
```

After reboot, verify:

```bash
sudo ringwallctl status
# Expected:
#   Sensor:     ebpf (open_hook=lsm/file_open lsm_blocking=true)
```

---

## First 5 Minutes: Wizard, Self-Test, Scan & Web UI

### 1. Run the Guided AI Setup Wizard (CLI or Web UI)

Ringwall enforces deterministically even with `ai.enabled: false`. To enable plain-language incident analysis and optional zero-day virtual-patch proposals using an **uncensored / abliterated model** (so real threat telemetry does not trigger false-positive safety refusals):

```bash
# Compare local (Ollama / llama.cpp) and cloud (Venice.ai / OpenRouter) uncensored providers:
ringwallctl providers

# Interactive guided wizard (auto-detects RAM/GPU/Ollama & runs a live 4-point refusal test):
sudo ringwallctl setup
sudo systemctl restart ringwalld
```

Or use the built-in **Web Setup Wizard & Live Monitor** (zero external CDNs, loopback-only):
1. Read the root-only bearer token:
   ```bash
   sudo cat /run/ringwall/api.token
   ```
2. Open `http://127.0.0.1:9443` in your browser and paste the bearer token.

### 2. Run the Built-In Attack Simulation & Verify Audit Chain

```bash
sudo ringwallctl status
sudo ringwallctl simulate
sudo ringwallctl incidents
sudo ringwallctl verify-log
```

`simulate` runs 5 safe built-in scenarios (without signaling real host processes) and verifies policy matching, deterministic-wins invariants, and tamper-evident SHA-256 audit log chaining.

### 3. Run a CVE, Stale-Library & Kernel Drift Scan

```bash
sudo ringwallctl scan
sudo ringwallctl patch --dry-run
```

By default, `scanner.allow_online_feeds` is `false` (strictly offline until you opt in). See [Self-Healing & A/B Updates](self-healing-and-ab-updates.md) to enable HTTPS OSV.dev + CISA KEV or configure an airgapped `offline_db_path`.

### 4. Optional: Enable Default-Deny `nftables` Firewall

`packaging/install.sh` leaves `enforcer.enable_nftables: false` on existing hosts so it never interrupts your existing SSH or firewall rules. To enable Ringwall's default-deny `nftables` ruleset and dynamic `blocked_v4`/`blocked_v6` egress sets:

1. Inspect `packaging/nftables.conf` and add an explicit allow rule for your management port if you rely on remote SSH!
2. Install `/etc/nftables.conf`, enable `nftables.service`, set `enforcer.enable_nftables: true` in `/etc/ringwall/ringwall.yaml`, and restart `ringwalld`.

---

## Host SSH Key Workflow (Zero-Exemption Default)

By default, Ringwall ships with **`sensor.lsm_allowed_ssh_exes: []`** and **no default executable exemptions** in `RW-AGENT-001`.

**Why:** Even legitimate OpenSSH client binaries running under the same UID can leak unencrypted on-disk keys (`ssh -F ~/.ssh/id_ed25519 x` leaks key lines to stderr; pointing `SSH_AUTH_SOCK` at a rogue Unix socket causes `ssh-add` to hand the raw private key to an attacker).

You have two options on a host workstation:
1. **Recommended (zero exemptions):** Use **hardware FIDO2 / YubiKey SSH keys** (`ed25519-sk`) or keep on-disk keys strictly out of `~/.ssh/id_*` while Ringwall blocks all direct reads.
2. **Explicit opt-in:** If you require local OpenSSH utilities to read passphrase-protected on-disk keys directly, opt in exact canonical binary paths in **both** files:

In `/etc/ringwall/ringwall.yaml`:
```yaml
sensor:
  lsm_allowed_ssh_exes:
    - /usr/bin/ssh-add
    - /usr/bin/ssh-keygen
```

In `/etc/ringwall/policies.d/10-ai-agent-guard.yaml` under `RW-AGENT-001` → `match`:
```yaml
      exclude_exe_paths:
        - '/usr/bin/ssh-add'
        - '/usr/bin/ssh-keygen'
```

Then restart `ringwalld`:
```bash
sudo systemctl restart ringwalld
```

Every opted-in binary is still protected in-kernel by fail-closed `lsm/mmap_file` (blocks `LD_PRELOAD` / `PKCS11Provider` across `fork()` and threads) and `task->ptrace != 0` + `lsm/ptrace_access_check` (blocks `strace` / `ptrace`).

---

## Troubleshooting

- **`open_hook=fentry/security_file_open lsm_blocking=false`:** Your kernel does not have `bpf` enabled in `/sys/kernel/security/lsm`. Follow the GRUB instructions above to activate Tier 1 synchronous `-EPERM` blocking.
- **`failed to read API token (/run/ringwall/api.token): permission denied`:** Expected for non-root users. Run `ringwallctl` with `sudo` (only `/run/ringwall-status/status.json` is world-readable for non-privileged health checks).
- **Check daemon logs:** `sudo journalctl -u ringwalld -n 100 --no-pager`
- **Validate custom policies before restarting:** `ringwallctl policy-check /etc/ringwall/policies.d`
