// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/scanner"
)

const (
	DefaultVirtualPatchTTL = 72 * time.Hour
	MaxVirtualPatchTTL     = 168 * time.Hour
)

var validVPIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// Protected executables that NO virtual patch (deterministic or AI-assisted) may ever block (anti-lockout invariant).
var protectedExePaths = map[string]bool{
	"/usr/local/bin/ringwalld":   true,
	"/usr/local/bin/ringwallctl": true,
	"/sbin/init":                 true,
	"/usr/sbin/init":             true,
	"/lib/systemd/systemd":       true,
	"/usr/lib/systemd/systemd":   true,
	"/bin/sh":                    true,
	"/usr/bin/sh":                true,
	"/bin/bash":                  true,
	"/usr/bin/bash":              true,
	"/bin/dash":                  true,
	"/usr/bin/dash":              true,
	"/usr/bin/login":             true,
	"/bin/login":                 true,
	"/sbin/agetty":               true,
	"/usr/sbin/agetty":           true,
	"/usr/bin/sudo":              true,
	"/usr/bin/su":                true,
	"/bin/su":                    true,
	"/usr/sbin/sshd":             true,
	"/usr/bin/apt-get":           true,
	"/usr/bin/dpkg":              true,
	"/usr/bin/systemctl":         true,
	"/bin/systemctl":             true,
}

// Overbroad globs that would brick the system if blocked.
var forbiddenGlobs = map[string]bool{
	"/": true, "/*": true, "/**": true, "**": true, "*": true,
	"/etc": true, "/etc/*": true, "/etc/**": true,
	"/usr": true, "/usr/*": true, "/usr/**": true,
	"/lib": true, "/lib/*": true, "/lib/**": true,
	"/bin": true, "/bin/*": true, "/bin/**": true,
	"/run": true, "/run/**": true, "/var/**": true,
	"/etc/passwd": true, "/etc/group": true,
}

// KernelBlocker is an optional hook implemented by the eBPF LSM sensor so active virtual patches
// can synchronously block vulnerable executable inodes in-kernel (lsm/bprm_check_security).
type KernelBlocker interface {
	SyncBlockedExecPaths(paths []string) (int, error)
}

// VirtualPatchManager manages TTL-bounded zero-day virtual patches with hard anti-lockout guardrails,
// live policy-engine synchronization, optional eBPF LSM exec-blocking, and automatic upstream-fix revocation.
type VirtualPatchManager struct {
	mu          sync.RWMutex
	patches     map[string]VirtualPatch
	engine      *policy.Engine
	blocker     KernelBlocker
	persistPath string
}

func NewVirtualPatchManager(engine *policy.Engine, blocker KernelBlocker, persistPath string) *VirtualPatchManager {
	return &VirtualPatchManager{
		patches:     make(map[string]VirtualPatch),
		engine:      engine,
		blocker:     blocker,
		persistPath: persistPath,
	}
}

// ValidateVirtualPatch enforces deterministic anti-lockout and schema invariants before any rule activates.
func ValidateVirtualPatch(vp VirtualPatch) error {
	if !validVPIDRe.MatchString(vp.ID) {
		return fmt.Errorf("invalid virtual patch id %q", vp.ID)
	}
	if len(vp.TargetExePaths) == 0 && len(vp.TargetPathGlobs) == 0 && len(vp.TargetPorts) == 0 {
		return fmt.Errorf("virtual patch %s must specify at least one target_exe_path, target_path_glob, or target_port", vp.ID)
	}
	switch vp.Action {
	case model.ActionWarn, model.ActionFreeze, model.ActionBlockEgress, model.ActionKill:
	default:
		return fmt.Errorf("virtual patch %s invalid action %q", vp.ID, vp.Action)
	}
	for _, exe := range vp.TargetExePaths {
		clean := filepath.ToSlash(filepath.Clean(exe))
		if !strings.HasPrefix(clean, "/") || strings.Contains(clean, "*") {
			return fmt.Errorf("virtual patch %s invalid executable path %q (must be exact canonical path)", vp.ID, exe)
		}
		if protectedExePaths[clean] {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target protected system binary %q", vp.ID, clean)
		}
	}
	for _, g := range vp.TargetPathGlobs {
		clean := strings.TrimSpace(filepath.ToSlash(g))
		if clean == "" || forbiddenGlobs[clean] {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot use overbroad glob %q", vp.ID, g)
		}
	}
	if vp.ExpiresAt.IsZero() {
		return fmt.Errorf("virtual patch %s must specify an explicit expires_at TTL", vp.ID)
	}
	return nil
}

// Apply validates, installs into policy.Engine, syncs to kernel LSM (if active), and persists to disk.
func (m *VirtualPatchManager) Apply(vp VirtualPatch) (VirtualPatch, error) {
	now := time.Now().UTC()
	if vp.CreatedAt.IsZero() {
		vp.CreatedAt = now
	}
	if vp.ExpiresAt.IsZero() {
		vp.ExpiresAt = now.Add(DefaultVirtualPatchTTL)
	}
	if vp.ExpiresAt.Sub(now) > MaxVirtualPatchTTL {
		vp.ExpiresAt = now.Add(MaxVirtualPatchTTL)
	}
	if vp.Action == "" {
		vp.Action = model.ActionFreeze
	}
	if err := ValidateVirtualPatch(vp); err != nil {
		return vp, err
	}

	rule := virtualPatchToRule(vp)
	if m.engine != nil {
		if err := m.engine.UpsertVirtualRule(rule, vp.ExpiresAt); err != nil {
			return vp, err
		}
	}

	m.mu.Lock()
	m.patches[vp.ID] = vp
	allExecs := m.collectBlockedExecPathsLocked(now)
	m.mu.Unlock()

	if m.blocker != nil {
		if n, err := m.blocker.SyncBlockedExecPaths(allExecs); err == nil && n > 0 && len(vp.TargetExePaths) > 0 {
			m.mu.Lock()
			vp.KernelLSMActive = true
			m.patches[vp.ID] = vp
			m.mu.Unlock()
		}
	}
	_ = m.persist()
	return vp, nil
}

// Revoke removes a virtual patch from policy.Engine, kernel LSM, and disk.
func (m *VirtualPatchManager) Revoke(id string) bool {
	m.mu.Lock()
	_, exists := m.patches[id]
	if exists {
		delete(m.patches, id)
	}
	allExecs := m.collectBlockedExecPathsLocked(time.Now().UTC())
	m.mu.Unlock()

	if !exists {
		return false
	}
	if m.engine != nil {
		m.engine.RemoveVirtualRule(id)
	}
	if m.blocker != nil {
		_, _ = m.blocker.SyncBlockedExecPaths(allExecs)
	}
	_ = m.persist()
	return true
}

// Reconcile expires TTL-elapsed virtual patches and automatically revokes patches whose CVE
// is no longer reported by the latest host vulnerability scan (upstream patch installed).
func (m *VirtualPatchManager) Reconcile(activeFindings []scanner.Finding, now time.Time) []string {
	activeCVEs := make(map[string]bool, len(activeFindings))
	for _, f := range activeFindings {
		if f.CVE != "" {
			activeCVEs[strings.ToUpper(f.CVE)] = true
		}
		if f.ID != "" {
			activeCVEs[strings.ToUpper(f.ID)] = true
		}
	}

	m.mu.Lock()
	var toRevoke []string
	for id, vp := range m.patches {
		if !vp.ExpiresAt.IsZero() && !now.Before(vp.ExpiresAt) {
			toRevoke = append(toRevoke, id)
			continue
		}
		// Auto-revoke CVE-tied patches when the latest scan confirms the CVE is fixed/absent.
		if vp.CVE != "" && vp.Source != "operator" && !activeCVEs[strings.ToUpper(vp.CVE)] {
			toRevoke = append(toRevoke, id)
		}
	}
	m.mu.Unlock()

	sort.Strings(toRevoke)
	var revoked []string
	for _, id := range toRevoke {
		if m.Revoke(id) {
			revoked = append(revoked, id)
		}
	}
	if m.engine != nil {
		m.engine.PruneExpiredVirtualRules(now)
	}
	return revoked
}

// List returns all active non-expired virtual patches sorted by ID.
func (m *VirtualPatchManager) List() []VirtualPatch {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]VirtualPatch, 0, len(m.patches))
	for _, vp := range m.patches {
		if !vp.ExpiresAt.IsZero() && !now.Before(vp.ExpiresAt) {
			continue
		}
		out = append(out, vp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SynthesizeDeterministic creates a safe deterministic containment virtual patch for an unpatched 0-day finding.
func SynthesizeDeterministic(f scanner.Finding, ttl time.Duration) (VirtualPatch, error) {
	if ttl <= 0 {
		ttl = DefaultVirtualPatchTTL
	}
	if ttl > MaxVirtualPatchTTL {
		ttl = MaxVirtualPatchTTL
	}
	cve := f.CVE
	if cve == "" {
		cve = f.ID
	}
	cleanID := regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(cve, "-")
	id := "VP-" + cleanID
	if len(id) > 64 {
		id = id[:64]
	}

	var safeBins []string
	for _, b := range f.RunningBins {
		c := filepath.ToSlash(filepath.Clean(b))
		if strings.HasPrefix(c, "/") && !strings.Contains(c, ".so") && !protectedExePaths[c] {
			safeBins = append(safeBins, c)
		}
	}
	// Fallback: check standard binary paths for the vulnerable package if no running binary hint was found.
	if len(safeBins) == 0 && ValidatePackageName(f.Package) == nil {
		for _, dir := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"} {
			cand := dir + f.Package
			if protectedExePaths[cand] {
				continue
			}
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				safeBins = append(safeBins, cand)
				break
			}
		}
	}

	if len(safeBins) == 0 {
		return VirtualPatch{}, fmt.Errorf("no safe non-protected executable target found for unpatched %s (%s)", cve, f.Package)
	}

	now := time.Now().UTC()
	return VirtualPatch{
		ID:             id,
		CVE:            cve,
		Package:        f.Package,
		TargetExePaths: safeBins,
		Action:         model.ActionFreeze,
		Rationale:      fmt.Sprintf("Temporary zero-day virtual patch containing unpatched %s in %s until upstream fix is available", cve, f.Package),
		Source:         "deterministic",
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
	}, nil
}

func virtualPatchToRule(vp VirtualPatch) policy.Rule {
	var evTypes []model.EventType
	if len(vp.TargetExePaths) > 0 {
		evTypes = append(evTypes, model.EventExec)
	}
	if len(vp.TargetPathGlobs) > 0 {
		evTypes = append(evTypes, model.EventOpen)
	}
	if len(vp.TargetPorts) > 0 {
		evTypes = append(evTypes, model.EventConnect)
	}
	return policy.Rule{
		ID:          vp.ID,
		Name:        fmt.Sprintf("Virtual Patch %s (%s)", vp.CVE, vp.Package),
		Category:    "virtual-patch",
		Severity:    model.SeverityCritical,
		Action:      vp.Action,
		Description: vp.Rationale,
		Match: policy.MatchSpec{
			EventTypes: evTypes,
			ExePaths:   vp.TargetExePaths,
			PathGlobs:  vp.TargetPathGlobs,
			DstPorts:   vp.TargetPorts,
		},
	}
}

func (m *VirtualPatchManager) collectBlockedExecPathsLocked(now time.Time) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, vp := range m.patches {
		if !vp.ExpiresAt.IsZero() && !now.Before(vp.ExpiresAt) {
			continue
		}
		if vp.Action != model.ActionFreeze && vp.Action != model.ActionKill {
			continue
		}
		for _, p := range vp.TargetExePaths {
			c := filepath.ToSlash(filepath.Clean(p))
			if protectedExePaths[c] {
				continue
			}
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (m *VirtualPatchManager) persist() error {
	if m.persistPath == "" {
		return nil
	}
	rules := []policy.Rule{}
	for _, vp := range m.List() {
		rules = append(rules, virtualPatchToRule(vp))
	}
	rf := policy.RuleFile{Rules: rules}
	data, err := yaml.Marshal(&rf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.persistPath), 0o700); err != nil {
		return err
	}
	tmp := m.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, m.persistPath)
}
