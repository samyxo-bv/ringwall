// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SysctlExpectation defines a kernel hardening parameter verified during posture scans.
type SysctlExpectation struct {
	ID          string
	Key         string // dot notation e.g. kernel.kptr_restrict
	Expected    string
	Severity    string
	Optional    bool // if file does not exist on this kernel (e.g. io_uring_disabled on 6.1), skip cleanly
	Description string
}

// BaselineHardeningSysctls returns the deterministic Ringwall kernel hardening baseline.
func BaselineHardeningSysctls() []SysctlExpectation {
	return []SysctlExpectation{
		{ID: "RW-DRIFT-001", Key: "kernel.kptr_restrict", Expected: "2", Severity: "medium", Description: "Hide kernel symbol pointers from unprivileged processes"},
		{ID: "RW-DRIFT-002", Key: "kernel.dmesg_restrict", Expected: "1", Severity: "low", Description: "Restrict kernel ring buffer access to privileged users"},
		{ID: "RW-DRIFT-003", Key: "kernel.unprivileged_bpf_disabled", Expected: "1", Severity: "high", Description: "Disable unprivileged eBPF syscall access"},
		{ID: "RW-DRIFT-004", Key: "kernel.unprivileged_userns_clone", Expected: "0", Severity: "high", Optional: true, Description: "Disable unprivileged user namespaces (blocks userns+chroot escapes)"},
		{ID: "RW-DRIFT-005", Key: "kernel.yama.ptrace_scope", Expected: "2", Severity: "high", Optional: true, Description: "Restrict ptrace to admin-only processes"},
		{ID: "RW-DRIFT-006", Key: "kernel.io_uring_disabled", Expected: "2", Severity: "high", Optional: true, Description: "Disable io_uring system-wide (Linux 6.6+)"},
		{ID: "RW-DRIFT-007", Key: "fs.protected_hardlinks", Expected: "1", Severity: "medium", Description: "Prevent unprivileged hardlink creation to unowned files"},
		{ID: "RW-DRIFT-008", Key: "fs.protected_symlinks", Expected: "1", Severity: "medium", Description: "Prevent symlink-following attacks in world-writable sticky dirs"},
		{ID: "RW-DRIFT-009", Key: "fs.suid_dumpable", Expected: "0", Severity: "medium", Description: "Prevent core dumps of setuid binaries"},
	}
}

// AuditDrift checks live kernel sysctls and critical Ringwall file permissions.
func AuditDrift(procSysRoot, tokenFile, auditLogPath string) []DriftItem {
	if procSysRoot == "" {
		procSysRoot = "/proc/sys"
	}
	var drift []DriftItem

	for _, exp := range BaselineHardeningSysctls() {
		rel := strings.ReplaceAll(exp.Key, ".", "/")
		full := filepath.Join(procSysRoot, filepath.FromSlash(rel))
		b, err := os.ReadFile(full)
		if err != nil {
			if exp.Optional || os.IsNotExist(err) {
				continue
			}
			continue
		}
		got := strings.TrimSpace(string(b))
		// For unprivileged_bpf_disabled, "2" (permanently disabled) is strictly stronger than "1".
		if exp.Key == "kernel.unprivileged_bpf_disabled" && (got == "1" || got == "2") {
			continue
		}
		if got != exp.Expected {
			drift = append(drift, DriftItem{
				ID:          exp.ID,
				Kind:        "sysctl",
				Target:      exp.Key,
				Expected:    exp.Expected,
				Actual:      got,
				Severity:    exp.Severity,
				AutoFixable: true,
				Description: exp.Description,
			})
		}
	}

	checkMode0600 := func(id, path, desc string) {
		if path == "" {
			return
		}
		st, err := os.Stat(path)
		if err != nil {
			return
		}
		perm := st.Mode().Perm()
		if perm&0o077 != 0 {
			drift = append(drift, DriftItem{
				ID:          id,
				Kind:        "file_perm",
				Target:      path,
				Expected:    "0600",
				Actual:      fmt.Sprintf("%04o", perm),
				Severity:    "critical",
				AutoFixable: true,
				Description: desc,
			})
		}
	}
	checkMode0600("RW-DRIFT-010", tokenFile, "Ringwall API bearer token must be strictly 0600 root-only")
	checkMode0600("RW-DRIFT-011", auditLogPath, "Ringwall audit hash-chain log must be strictly 0600 root-only")

	return drift
}
