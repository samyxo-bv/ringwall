// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/samyxo-bv/ringwall/internal/scanner"
)

// Strict Debian/APK package name regex: starts with alphanumeric, zero leading dashes or shell metacharacters.
var validPkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)

// Strict systemd unit regex: rejects flags, path traversal, and shell characters.
var validUnitNameRe = regexp.MustCompile(`^[a-zA-Z0-9@_.-]{1,128}\.service$`)

// Protected units that must NEVER be restarted automatically (anti-lockout invariant).
var protectedUnits = map[string]bool{
	"ringwalld.service": true,
	"dbus.service":      true,
	"dbus-broker.service": true,
	"ssh.service":       true,
	"sshd.service":      true,
	"systemd-journald.service": true,
	"systemd-logind.service":   true,
	"systemd-udevd.service":    true,
	"systemd-networkd.service": true,
	"networking.service":       true,
	"NetworkManager.service":   true,
}

// CmdRunner abstracts external OS commands for deterministic unit testing without root.
type CmdRunner interface {
	Run(ctx context.Context, env []string, name string, args ...string) (string, error)
}

type execCmdRunner struct{}

func (execCmdRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ValidatePackageName rejects anything that could act as a flag or injection vector.
func ValidatePackageName(pkg string) error {
	if !validPkgNameRe.MatchString(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}
	return nil
}

// IsProtectedUnit returns true if automatic restart could sever admin access or stop Ringwall itself.
func IsProtectedUnit(unit string) bool {
	if protectedUnits[unit] {
		return true
	}
	if strings.HasPrefix(unit, "getty@") || strings.HasPrefix(unit, "serial-getty@") || strings.HasPrefix(unit, "systemd-") || strings.HasPrefix(unit, "user@") {
		return true
	}
	return false
}

// PatchPackages applies security-only upgrades for validated Debian/Ubuntu packages using direct argv execution.
func PatchPackages(ctx context.Context, runner CmdRunner, pkgs []scanner.Finding, dryRun bool) []PackagePatchOutcome {
	if runner == nil {
		runner = execCmdRunner{}
	}
	seen := make(map[string]scanner.Finding)
	var names []string
	var results []PackagePatchOutcome

	for _, f := range pkgs {
		if !f.HasUpstreamFix {
			continue
		}
		if err := ValidatePackageName(f.Package); err != nil {
			results = append(results, PackagePatchOutcome{
				Package: f.Package,
				CVE:     f.CVE,
				Status:  "failed",
				Detail:  err.Error(),
			})
			continue
		}
		if _, dup := seen[f.Package]; dup {
			continue
		}
		seen[f.Package] = f
		names = append(names, f.Package)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return results
	}

	if dryRun {
		for _, name := range names {
			f := seen[name]
			results = append(results, PackagePatchOutcome{
				Package:       name,
				CVE:           f.CVE,
				TargetVersion: f.FixedVersion,
				Status:        "dry_run",
				Detail:        "would run apt-get install --only-upgrade " + name,
			})
		}
		return results
	}

	env := []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"}
	if out, err := runner.Run(ctx, env, "apt-get", "update", "-q"); err != nil {
		for _, name := range names {
			f := seen[name]
			results = append(results, PackagePatchOutcome{
				Package: name,
				CVE:     f.CVE,
				Status:  "failed",
				Detail:  fmt.Sprintf("apt-get update failed: %v (%s)", err, trimDetail(out)),
			})
		}
		return results
	}

	// Upgrade each validated package individually so one broken package never blocks other critical fixes.
	for _, name := range names {
		f := seen[name]
		args := []string{
			"install", "-y", "--only-upgrade", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"--", name,
		}
		out, err := runner.Run(ctx, env, "apt-get", args...)
		if err != nil {
			results = append(results, PackagePatchOutcome{
				Package:       name,
				CVE:           f.CVE,
				TargetVersion: f.FixedVersion,
				Status:        "failed",
				Detail:        fmt.Sprintf("%v (%s)", err, trimDetail(out)),
			})
			continue
		}
		results = append(results, PackagePatchOutcome{
			Package:       name,
			CVE:           f.CVE,
			TargetVersion: f.FixedVersion,
			Status:        "patched",
			Detail:        "upgraded via apt-get --only-upgrade",
		})
	}
	return results
}

// RestartStaleServices restarts non-protected systemd services still mapping deleted libraries,
// then verifies each restarted unit returned to active state.
func RestartStaleServices(ctx context.Context, runner CmdRunner, stale []scanner.StaleProcess, dryRun bool) []ServiceRestartOutcome {
	if runner == nil {
		runner = execCmdRunner{}
	}
	units := make(map[string]bool)
	for _, sp := range stale {
		if sp.SystemdUnit != "" {
			units[sp.SystemdUnit] = true
		}
	}
	sorted := make([]string, 0, len(units))
	for u := range units {
		sorted = append(sorted, u)
	}
	sort.Strings(sorted)

	var out []ServiceRestartOutcome
	for _, unit := range sorted {
		if !validUnitNameRe.MatchString(unit) {
			out = append(out, ServiceRestartOutcome{Unit: unit, Status: "failed", Detail: "invalid unit name"})
			continue
		}
		if IsProtectedUnit(unit) {
			out = append(out, ServiceRestartOutcome{
				Unit:   unit,
				Status: "skipped_protected",
				Detail: "protected system/admin unit (anti-lockout policy; restart manually during maintenance)",
			})
			continue
		}
		if dryRun {
			out = append(out, ServiceRestartOutcome{
				Unit:   unit,
				Status: "dry_run",
				Detail: "would run systemctl restart " + unit,
			})
			continue
		}
		if res, err := runner.Run(ctx, nil, "systemctl", "restart", "--", unit); err != nil {
			out = append(out, ServiceRestartOutcome{
				Unit:   unit,
				Status: "failed",
				Detail: fmt.Sprintf("restart failed: %v (%s)", err, trimDetail(res)),
			})
			continue
		}
		// Post-restart health check.
		activeOut, activeErr := runner.Run(ctx, nil, "systemctl", "is-active", "--", unit)
		if activeErr != nil || strings.TrimSpace(activeOut) != "active" {
			out = append(out, ServiceRestartOutcome{
				Unit:   unit,
				Status: "failed",
				Detail: fmt.Sprintf("post-restart health check not active: %q (%v)", activeOut, activeErr),
			})
			continue
		}
		out = append(out, ServiceRestartOutcome{
			Unit:   unit,
			Status: "restarted",
			Detail: "restarted and verified active",
		})
	}
	return out
}

// FixDrift automatically remediates allowed baseline sysctls and 0600 Ringwall file permissions.
func FixDrift(procSysRoot string, items []scanner.DriftItem, dryRun bool) []DriftFixOutcome {
	if procSysRoot == "" {
		procSysRoot = "/proc/sys"
	}
	allowedSysctl := make(map[string]string)
	for _, b := range scanner.BaselineHardeningSysctls() {
		allowedSysctl[b.Key] = b.Expected
	}

	var out []DriftFixOutcome
	for _, d := range items {
		if !d.AutoFixable {
			continue
		}
		switch d.Kind {
		case "sysctl":
			expVal, ok := allowedSysctl[d.Target]
			if !ok {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "failed", Detail: "sysctl not in approved baseline allowlist"})
				continue
			}
			if dryRun {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "dry_run", Detail: "would set " + d.Target + "=" + expVal})
				continue
			}
			rel := strings.ReplaceAll(d.Target, ".", "/")
			full := filepath.Join(procSysRoot, filepath.FromSlash(rel))
			if err := os.WriteFile(full, []byte(expVal+"\n"), 0o644); err != nil {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "failed", Detail: err.Error()})
				continue
			}
			out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "fixed", Detail: "restored to " + expVal})

		case "file_perm":
			modeVal, err := strconv.ParseUint(d.Expected, 8, 32)
			if err != nil {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "failed", Detail: "invalid expected mode"})
				continue
			}
			if dryRun {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "dry_run", Detail: "would chmod " + d.Expected + " " + d.Target})
				continue
			}
			if err := os.Chmod(d.Target, os.FileMode(modeVal)); err != nil {
				out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "failed", Detail: err.Error()})
				continue
			}
			out = append(out, DriftFixOutcome{ID: d.ID, Target: d.Target, Status: "fixed", Detail: "chmod " + d.Expected})
		}
	}
	return out
}

func trimDetail(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 180 {
		return s[:180] + "..."
	}
	return s
}
