// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/scanner"
)

const (
	DefaultVirtualPatchTTL = 72 * time.Hour
	MaxVirtualPatchTTL     = 168 * time.Hour
)

var validVPIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// Protected executables (canonical + usrmerge + OpenSSH >= 9.8 helpers + recovery tools) that NO
// virtual patch may ever block (anti-lockout invariant). Supplemented at runtime with /etc/shells
// and live (dev, ino) inode resolution so symlinks like /usr/bin/rbash -> bash can NEVER bypass it.
var protectedExePaths = map[string]bool{
	"/usr/local/bin/ringwalld":     true,
	"/usr/local/bin/ringwallctl":   true,
	"/sbin/init":                   true,
	"/usr/sbin/init":               true,
	"/lib/systemd/systemd":         true,
	"/usr/lib/systemd/systemd":     true,
	"/bin/sh":                      true,
	"/usr/bin/sh":                  true,
	"/bin/bash":                    true,
	"/usr/bin/bash":                true,
	"/bin/rbash":                   true,
	"/usr/bin/rbash":               true,
	"/bin/dash":                    true,
	"/usr/bin/dash":                true,
	"/usr/bin/zsh":                 true,
	"/bin/zsh":                     true,
	"/usr/bin/login":               true,
	"/bin/login":                   true,
	"/sbin/agetty":                 true,
	"/usr/sbin/agetty":             true,
	"/usr/bin/sudo":                true,
	"/bin/sudo":                    true,
	"/usr/bin/su":                  true,
	"/bin/su":                      true,
	"/usr/bin/passwd":              true,
	"/bin/passwd":                  true,
	"/usr/bin/ssh":                 true,
	"/bin/ssh":                     true,
	"/usr/sbin/sshd":                   true,
	"/sbin/sshd":                       true,
	"/usr/lib/openssh/sshd-session":    true,
	"/usr/lib/openssh/sshd-auth":       true,
	"/lib/openssh/sshd-session":        true,
	"/lib/openssh/sshd-auth":           true,
	"/usr/libexec/openssh/sshd-session": true,
	"/usr/libexec/openssh/sshd-auth":   true,
	"/usr/libexec/sshd-session":        true,
	"/usr/libexec/sshd-auth":           true,
	"/lib/systemd/systemd-executor":    true,
	"/usr/lib/systemd/systemd-executor": true,
	"/lib/systemd/systemd-journald":    true,
	"/usr/lib/systemd/systemd-journald": true,
	"/lib/systemd/systemd-logind":      true,
	"/usr/lib/systemd/systemd-logind":  true,
	"/lib/systemd/systemd-udevd":       true,
	"/usr/lib/systemd/systemd-udevd":   true,
	"/lib/systemd/systemd-resolved":    true,
	"/usr/lib/systemd/systemd-resolved": true,
	"/lib/systemd/systemd-networkd":    true,
	"/usr/lib/systemd/systemd-networkd": true,
	"/usr/bin/dbus-daemon":             true,
	"/bin/dbus-daemon":                 true,
	"/usr/bin/dbus-broker":             true,
	"/usr/bin/apt-get":                 true,
	"/bin/apt-get":                     true,
	"/usr/bin/apt":                     true,
	"/bin/apt":                         true,
	"/usr/bin/dpkg":                    true,
	"/bin/dpkg":                        true,
	"/usr/bin/systemctl":               true,
	"/bin/systemctl":                   true,
	"/usr/sbin/reboot":                 true,
	"/sbin/reboot":                     true,
	"/usr/sbin/shutdown":               true,
	"/sbin/shutdown":                   true,
}

// Critical path prefixes that virtual patches must NEVER match (covers PAM, sudoers, SSH,
// systemd, login profiles, dynamic linker, root home, and Ringwall control state).
var forbiddenPathPrefixes = []string{
	"/root",
	"/boot",
	"/etc/ssh",
	"/etc/pam",
	"/etc/pam.d",
	"/etc/pam.conf",
	"/etc/systemd",
	"/etc/ringwall",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/profile",
	"/etc/profile.d",
	"/etc/bash.bashrc",
	"/etc/environment",
	"/etc/ld.so.preload",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/lib/systemd",
	"/usr/lib/systemd",
	"/usr/lib/openssh",
	"/usr/libexec/openssh",
	"/run/ringwall",
	"/var/lib/ringwall",
	"/proc",
	"/sys",
	"/dev",
}

// Critical login/shell/SSH filenames that virtual patches must NEVER match anywhere on disk.
var forbiddenLeafNames = map[string]bool{
	".profile":         true,
	".bashrc":          true,
	".bash_profile":    true,
	".bash_login":      true,
	".zshrc":           true,
	".zprofile":        true,
	".login":           true,
	".cshrc":           true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"known_hosts":      true,
}

// Critical admin/infrastructure ports forbidden for automated/AI virtual patches.
var protectedAutoPorts = map[uint16]bool{
	22:   true, // SSH
	53:   true, // DNS
	80:   true, // HTTP
	443:  true, // HTTPS
	9443: true, // Ringwall control API
}

// KernelBlocker is an optional hook implemented by the eBPF LSM sensor so active virtual patches
// can synchronously block vulnerable executable inodes in-kernel (lsm/bprm_check_security).
type KernelBlocker interface {
	SyncBlockedExecPaths(paths []string) (int, error)
}

type persistedVPFile struct {
	Version int            `json:"version"`
	Patches []VirtualPatch `json:"patches"`
}

// VirtualPatchManager manages TTL-bounded zero-day virtual patches with inode-level anti-lockout
// guardrails, live policy-engine synchronization, optional eBPF LSM exec-blocking, JSON persistence
// outside policy_dirs, and fail-closed automatic upstream-fix revocation.
type VirtualPatchManager struct {
	mu              sync.RWMutex
	persistMu       sync.Mutex
	patches         map[string]VirtualPatch
	protectedInodes map[inodeID]string
	protectedPaths  map[string]bool
	engine          *policy.Engine
	blocker         KernelBlocker
	persistPath     string
}

type protectedExecSetter interface {
	SetProtectedExecPaths(paths []string)
}

func NewVirtualPatchManager(engine *policy.Engine, blocker KernelBlocker, persistPath string) *VirtualPatchManager {
	m := &VirtualPatchManager{
		patches:     make(map[string]VirtualPatch),
		engine:      engine,
		blocker:     blocker,
		persistPath: persistPath,
	}
	m.protectedPaths, m.protectedInodes = buildProtectedBinaryIndex("/etc/shells", nil)
	if engine != nil {
		engine.SetVirtualPatchExeGuard(m.IsProtectedExe)
	}
	m.syncProtectedToBlocker()
	return m
}

func (m *VirtualPatchManager) syncProtectedToBlocker() {
	ps, ok := m.blocker.(protectedExecSetter)
	if !ok {
		return
	}
	m.mu.RLock()
	paths := make([]string, 0, len(m.protectedPaths))
	for p := range m.protectedPaths {
		paths = append(paths, p)
	}
	m.mu.RUnlock()
	ps.SetProtectedExecPaths(paths)
}

// IsProtectedExe returns true if exe (or live /proc/<pid>/exe) matches any protected system
// binary by canonical path, usrmerge alias, symlink target, or live (dev, ino) inode.
// Used by policy.Engine to guarantee virtual patches can NEVER freeze or kill sshd, systemd,
// login shells, apt/dpkg, or ringwalld (P0-A runtime invariant).
func (m *VirtualPatchManager) IsProtectedExe(pid int, exe string) bool {
	m.mu.RLock()
	protPaths := m.protectedPaths
	protInodes := m.protectedInodes
	m.mu.RUnlock()

	checkPath := func(raw string) bool {
		raw = strings.TrimSpace(strings.TrimSuffix(raw, " (deleted)"))
		if raw == "" {
			return false
		}
		clean := filepath.ToSlash(filepath.Clean(raw))
		if protPaths[clean] {
			return true
		}
		for _, alias := range usrMergeAliases(clean) {
			if protPaths[alias] {
				return true
			}
		}
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			rc := filepath.ToSlash(filepath.Clean(resolved))
			if protPaths[rc] {
				return true
			}
		}
		if id, ok := statInodeID(clean); ok {
			if _, hit := protInodes[id]; hit {
				return true
			}
		}
		return false
	}

	if checkPath(exe) {
		return true
	}
	if pid > 0 {
		procExe := fmt.Sprintf("/proc/%d/exe", pid)
		if id, ok := statInodeID(procExe); ok {
			if _, hit := protInodes[id]; hit {
				return true
			}
		}
		if target, err := os.Readlink(procExe); err == nil {
			if checkPath(target) {
				return true
			}
		}
	}
	return false
}

// AddProtectedBinaryForTest registers an extra path (and its live inode) in the anti-lockout set.
func (m *VirtualPatchManager) AddProtectedBinaryForTest(p string) {
	m.mu.Lock()
	clean := filepath.ToSlash(filepath.Clean(p))
	m.protectedPaths[clean] = true
	if id, ok := statInodeID(clean); ok {
		m.protectedInodes[id] = clean
	}
	m.mu.Unlock()
	m.syncProtectedToBlocker()
}

func buildProtectedBinaryIndex(shellsPath string, extra []string) (map[string]bool, map[inodeID]string) {
	paths := make(map[string]bool, len(protectedExePaths)+16)
	addPath := func(p string) {
		c := filepath.ToSlash(filepath.Clean(strings.TrimSpace(p)))
		if !strings.HasPrefix(c, "/") {
			return
		}
		paths[c] = true
		for _, alias := range usrMergeAliases(c) {
			paths[alias] = true
		}
	}
	for p := range protectedExePaths {
		addPath(p)
	}
	for _, p := range extra {
		addPath(p)
	}
	// Dynamically include distro systemd and OpenSSH helper executables (P2-7).
	for _, pat := range []string{
		"/lib/systemd/systemd*",
		"/usr/lib/systemd/systemd*",
		"/usr/lib/openssh/*",
		"/lib/openssh/*",
		"/usr/libexec/openssh/*",
	} {
		if matches, err := filepath.Glob(pat); err == nil {
			for _, m := range matches {
				addPath(m)
			}
		}
	}
	if shellsPath != "" {
		if f, err := os.Open(shellsPath); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				addPath(line)
			}
			_ = f.Close()
		}
	}

	inodes := make(map[inodeID]string, len(paths))
	for p := range paths {
		if id, ok := statInodeID(p); ok {
			inodes[id] = p
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			rc := filepath.ToSlash(filepath.Clean(resolved))
			paths[rc] = true
			if id, ok := statInodeID(rc); ok {
				inodes[id] = rc
			}
		}
	}
	return paths, inodes
}

func usrMergeAliases(clean string) []string {
	pairs := [][2]string{
		{"/bin/", "/usr/bin/"},
		{"/sbin/", "/usr/sbin/"},
		{"/lib/", "/usr/lib/"},
		{"/lib64/", "/usr/lib64/"},
	}
	var out []string
	for _, pair := range pairs {
		if strings.HasPrefix(clean, pair[0]) {
			out = append(out, pair[1]+strings.TrimPrefix(clean, pair[0]))
		} else if strings.HasPrefix(clean, pair[1]) {
			out = append(out, pair[0]+strings.TrimPrefix(clean, pair[1]))
		}
	}
	return out
}

// ValidateVirtualPatch enforces deterministic inode-aware anti-lockout and schema invariants.
func ValidateVirtualPatch(vp VirtualPatch) error {
	paths, inodes := buildProtectedBinaryIndex("/etc/shells", nil)
	return validateVirtualPatchWithIndex(vp, paths, inodes)
}

func validateVirtualPatchWithIndex(vp VirtualPatch, protPaths map[string]bool, protInodes map[inodeID]string) error {
	if !validVPIDRe.MatchString(vp.ID) {
		return fmt.Errorf("invalid virtual patch id %q", vp.ID)
	}
	if len(vp.TargetExePaths) == 0 && len(vp.TargetPathGlobs) == 0 && len(vp.TargetPorts) == 0 {
		return fmt.Errorf("virtual patch %s must specify at least one target_exe_path, target_path_glob, or target_port", vp.ID)
	}

	// AI-assisted patches may ONLY use freeze or block_egress — NEVER kill (P0-1).
	if vp.Source == "ai_assisted" {
		if vp.Action != model.ActionFreeze && vp.Action != model.ActionBlockEgress {
			return fmt.Errorf("anti-lockout rejected: AI virtual patch %s may only use freeze or block_egress (got %q)", vp.ID, vp.Action)
		}
	} else {
		switch vp.Action {
		case model.ActionWarn, model.ActionFreeze, model.ActionBlockEgress, model.ActionKill:
		default:
			return fmt.Errorf("virtual patch %s invalid action %q", vp.ID, vp.Action)
		}
	}

	for _, exe := range vp.TargetExePaths {
		if strings.ContainsAny(exe, "*?[") {
			return fmt.Errorf("virtual patch %s invalid executable path %q (wildcards forbidden)", vp.ID, exe)
		}
		clean := filepath.ToSlash(filepath.Clean(exe))
		if !strings.HasPrefix(clean, "/") || clean == "/" {
			return fmt.Errorf("virtual patch %s invalid executable path %q (must be exact canonical path)", vp.ID, exe)
		}
		// Check canonical path AND usrmerge aliases against protected binary list.
		if protPaths[clean] {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target protected system binary %q", vp.ID, clean)
		}
		for _, alias := range usrMergeAliases(clean) {
			if protPaths[alias] {
				return fmt.Errorf("anti-lockout rejected: virtual patch %s targets usrmerge alias %q of protected binary %q", vp.ID, clean, alias)
			}
		}
		// Reject symlinks explicitly (defeats /usr/bin/rbash -> bash, /sbin/sshd -> /usr/sbin/sshd, etc.).
		if linfo, err := os.Lstat(clean); err == nil {
			if linfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target symlink %q", vp.ID, clean)
			}
			if resolved, rerr := filepath.EvalSymlinks(clean); rerr == nil {
				rc := filepath.ToSlash(filepath.Clean(resolved))
				if protPaths[rc] {
					return fmt.Errorf("anti-lockout rejected: virtual patch %s resolves to protected binary %q", vp.ID, rc)
				}
			}
		}
		// Inode-level check (dev, ino) defeats hardlinks or unmapped aliases to any protected binary.
		if id, ok := statInodeID(clean); ok {
			if protBin, hit := protInodes[id]; hit {
				return fmt.Errorf("anti-lockout rejected: virtual patch %s matches inode of protected binary %q", vp.ID, protBin)
			}
		}
	}

	for _, g := range vp.TargetPathGlobs {
		if err := validateVirtualPatchGlob(vp.ID, g); err != nil {
			return err
		}
	}

	isAutomated := vp.Source == "ai_assisted" || vp.Source == "deterministic"
	for _, port := range vp.TargetPorts {
		if port == 0 {
			return fmt.Errorf("virtual patch %s invalid port 0", vp.ID)
		}
		if isAutomated && protectedAutoPorts[port] {
			return fmt.Errorf("anti-lockout rejected: automated virtual patch %s cannot block protected port %d", vp.ID, port)
		}
	}

	if vp.ExpiresAt.IsZero() {
		return fmt.Errorf("virtual patch %s must specify an explicit expires_at TTL", vp.ID)
	}
	return nil
}

// validateVirtualPatchGlob forbids '**' wildcards, root/top-level globs, critical system/login prefixes,
// SSH/shell startup dotfiles, and requires at least 3 fixed non-wildcard path components before any wildcard.
func validateVirtualPatchGlob(vpID, raw string) error {
	g := strings.TrimSpace(filepath.ToSlash(raw))
	if !strings.HasPrefix(g, "/") || g == "/" {
		return fmt.Errorf("anti-lockout rejected: virtual patch %s invalid path glob %q", vpID, raw)
	}
	if strings.Contains(g, "**") || strings.Contains(g, "..") {
		return fmt.Errorf("anti-lockout rejected: virtual patch %s forbids '**' and '..' in glob %q", vpID, raw)
	}
	clean := filepath.ToSlash(filepath.Clean(g))
	for _, pref := range forbiddenPathPrefixes {
		if clean == pref || strings.HasPrefix(clean, pref+"/") {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target protected prefix %q", vpID, pref)
		}
	}
	segs := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	isHomePath := len(segs) > 0 && segs[0] == "home"
	for _, seg := range segs {
		if seg == ".ssh" {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target .ssh path %q", vpID, raw)
		}
		if forbiddenLeafNames[seg] {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target login/shell file %q", vpID, raw)
		}
		if isHomePath && strings.HasPrefix(seg, ".") {
			return fmt.Errorf("anti-lockout rejected: virtual patch %s cannot target user dotfile %q", vpID, raw)
		}
	}
	fixedPrefix := 0
	for _, seg := range segs {
		if seg == "" || strings.ContainsAny(seg, "*?[") {
			break
		}
		fixedPrefix++
	}
	if fixedPrefix < 3 {
		return fmt.Errorf("anti-lockout rejected: virtual patch %s glob %q must have at least 3 fixed path components before any wildcard", vpID, raw)
	}
	return nil
}

// LoadPersisted reloads TTL-bounded virtual patches from the JSON state file (outside policy_dirs),
// drops expired entries, re-validates every entry against anti-lockout rules, re-installs valid rules
// into policy.Engine, and re-syncs kernel LSM exec blocking.
func (m *VirtualPatchManager) LoadPersisted() (int, error) {
	if m.persistPath == "" {
		return 0, nil
	}
	b, err := os.ReadFile(m.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var pf persistedVPFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return 0, fmt.Errorf("parse virtual patch store %s: %w", m.persistPath, err)
	}

	now := time.Now().UTC()
	loaded := 0
	dirty := false
	for _, vp := range pf.Patches {
		if !vp.ExpiresAt.IsZero() && !now.Before(vp.ExpiresAt) {
			dirty = true
			continue // drop expired patch
		}
		if _, err := m.applyInternal(vp, false); err != nil {
			dirty = true
			continue // reject any patch violating updated anti-lockout rules
		}
		loaded++
	}
	if dirty {
		_ = m.persist()
	}
	return loaded, nil
}

// Apply validates, installs into policy.Engine, syncs to kernel LSM (if active), and persists JSON to disk.
func (m *VirtualPatchManager) Apply(vp VirtualPatch) (VirtualPatch, error) {
	return m.applyInternal(vp, true)
}

func (m *VirtualPatchManager) applyInternal(vp VirtualPatch, writeDisk bool) (VirtualPatch, error) {
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

	m.mu.RLock()
	protPaths := m.protectedPaths
	protInodes := m.protectedInodes
	m.mu.RUnlock()

	if err := validateVirtualPatchWithIndex(vp, protPaths, protInodes); err != nil {
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
	if writeDisk {
		_ = m.persist()
	}
	return vp, nil
}

// Revoke removes a virtual patch from policy.Engine, kernel LSM, and persisted JSON state.
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

// Reconcile expires TTL-elapsed virtual patches and FAIL-CLOSED auto-revokes CVE patches ONLY when
// the scan report is strictly Complete (0 feed errors, non-empty package inventory, not truncated)
// and positively confirms the package is present without the CVE remaining open (P1-3).
func (m *VirtualPatchManager) Reconcile(rep scanner.ScanReport, now time.Time) []string {
	activeCVEs := make(map[string]bool, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.CVE != "" {
			activeCVEs[strings.ToUpper(f.CVE)] = true
		}
		if f.ID != "" {
			activeCVEs[strings.ToUpper(f.ID)] = true
		}
	}

	// Fail-closed: NEVER auto-revoke unexpired CVE virtual patches on incomplete/errored scans!
	canAutoRevokeCVE := rep.Complete && len(rep.FeedErrors) == 0 && rep.PackageCount > 0 && !rep.Truncated

	m.mu.Lock()
	var toRevoke []string
	for id, vp := range m.patches {
		if !vp.ExpiresAt.IsZero() && !now.Before(vp.ExpiresAt) {
			toRevoke = append(toRevoke, id)
			continue
		}
		if !canAutoRevokeCVE {
			continue
		}
		if vp.CVE != "" && vp.Source != "operator" && !activeCVEs[strings.ToUpper(vp.CVE)] {
			// Require positive inventory verification: package was inspected (or removed from host).
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

	protPaths, protInodes := buildProtectedBinaryIndex("/etc/shells", nil)
	isSafeTarget := func(p string) bool {
		c := filepath.ToSlash(filepath.Clean(p))
		if !strings.HasPrefix(c, "/") || strings.Contains(c, ".so") || protPaths[c] {
			return false
		}
		for _, a := range usrMergeAliases(c) {
			if protPaths[a] {
				return false
			}
		}
		if linfo, err := os.Lstat(c); err == nil && linfo.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if id, ok := statInodeID(c); ok {
			if _, hit := protInodes[id]; hit {
				return false
			}
		}
		return true
	}

	var safeBins []string
	for _, b := range f.RunningBins {
		if isSafeTarget(b) {
			safeBins = append(safeBins, filepath.ToSlash(filepath.Clean(b)))
		}
	}
	if len(safeBins) == 0 && ValidatePackageName(f.Package) == nil {
		for _, dir := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"} {
			cand := dir + f.Package
			if !isSafeTarget(cand) {
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
			if m.protectedPaths[c] {
				continue
			}
			// Re-verify live filesystem entry on EVERY sync so post-validation symlink swaps or
			// hardlinks pointing to a protected binary can NEVER enter lsm_deny_exec_inodes (P1-B).
			linfo, err := os.Lstat(c)
			if err != nil || !linfo.Mode().IsRegular() {
				continue
			}
			if resolved, rerr := filepath.EvalSymlinks(c); rerr == nil {
				if m.protectedPaths[filepath.ToSlash(filepath.Clean(resolved))] {
					continue
				}
			}
			if id, ok := statInodeID(c); ok {
				if _, hit := m.protectedInodes[id]; hit {
					continue
				}
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
	m.persistMu.Lock()
	defer m.persistMu.Unlock()

	pf := persistedVPFile{
		Version: 1,
		Patches: m.List(),
	}
	data, err := json.MarshalIndent(&pf, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".vpatches-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, m.persistPath)
}
