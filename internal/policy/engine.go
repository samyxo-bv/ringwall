// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/samyxo-bv/ringwall/internal/model"
)

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string         `yaml:"id"`
	Name        string         `yaml:"name"`
	Category    string         `yaml:"category"`
	Severity    model.Severity `yaml:"severity"`
	Action      model.Action   `yaml:"action"`
	MITRE       string         `yaml:"mitre,omitempty"`
	Description string         `yaml:"description"`
	Match       MatchSpec      `yaml:"match"`

	compiledCmdRegex []*regexp.Regexp
}

type MatchSpec struct {
	EventTypes       []model.EventType `yaml:"event_types,omitempty"`
	CommIn           []string          `yaml:"comm_in,omitempty"`
	ExePaths         []string          `yaml:"exe_paths,omitempty"`
	ExcludeExePaths  []string          `yaml:"exclude_exe_paths,omitempty"`
	PathGlobs        []string          `yaml:"path_globs,omitempty"`
	ExcludePathGlobs []string          `yaml:"exclude_path_globs,omitempty"`
	CmdlineRegex     []string          `yaml:"cmdline_regex,omitempty"`
	DestructiveRM    bool              `yaml:"destructive_rm,omitempty"`
	AncestorAny      []string          `yaml:"ancestor_any,omitempty"`
	RequireWrite     bool              `yaml:"require_write,omitempty"`
	DstPorts         []uint16          `yaml:"dst_ports,omitempty"`
	DstIPNotPrivate  bool              `yaml:"dst_ip_not_private,omitempty"`
}

type allowEntry struct {
	ruleID string
	exe    string
	path   string
}

type virtualRuleEntry struct {
	rule      Rule
	expiresAt time.Time
}

type Engine struct {
	mu           sync.RWMutex
	rules        []Rule
	virtualRules map[string]virtualRuleEntry
	runtimeAllow []allowEntry
}

func NewEngine(rules []Rule) (*Engine, error) {
	compiled := make([]Rule, 0, len(rules))
	for i := range rules {
		r := rules[i]
		if r.ID == "" || r.Name == "" {
			return nil, fmt.Errorf("policy rule at index %d missing id or name", i)
		}
		if r.Action == "" {
			r.Action = model.ActionWarn
		}
		if r.Severity == "" {
			r.Severity = model.SeverityMedium
		}
		for _, expr := range r.Match.CmdlineRegex {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("rule %s invalid cmdline_regex %q: %w", r.ID, expr, err)
			}
			r.compiledCmdRegex = append(r.compiledCmdRegex, re)
		}
		compiled = append(compiled, r)
	}
	return &Engine{
		rules:        compiled,
		virtualRules: make(map[string]virtualRuleEntry),
	}, nil
}

func LoadDirs(dirs []string) (*Engine, error) {
	var all []Rule
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				continue
			}
			p := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("read policy file %s: %w", p, err)
			}
			var rf RuleFile
			if err := yaml.Unmarshal(data, &rf); err != nil {
				return nil, fmt.Errorf("parse policy file %s: %w", p, err)
			}
			all = append(all, rf.Rules...)
		}
	}
	return NewEngine(all)
}

func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now().UTC()
	activeVirt := 0
	for _, v := range e.virtualRules {
		if v.expiresAt.IsZero() || now.Before(v.expiresAt) {
			activeVirt++
		}
	}
	return len(e.rules) + activeVirt
}

// UpsertVirtualRule installs or updates a temporary TTL-bounded virtual-patch containment rule at runtime.
func (e *Engine) UpsertVirtualRule(r Rule, expiresAt time.Time) error {
	if r.ID == "" || r.Name == "" {
		return fmt.Errorf("virtual rule missing id or name")
	}
	if r.Action == "" {
		r.Action = model.ActionFreeze
	}
	if r.Severity == "" {
		r.Severity = model.SeverityHigh
	}
	r.compiledCmdRegex = nil
	for _, expr := range r.Match.CmdlineRegex {
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("virtual rule %s invalid cmdline_regex %q: %w", r.ID, expr, err)
		}
		r.compiledCmdRegex = append(r.compiledCmdRegex, re)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.virtualRules == nil {
		e.virtualRules = make(map[string]virtualRuleEntry)
	}
	e.virtualRules[r.ID] = virtualRuleEntry{rule: r, expiresAt: expiresAt.UTC()}
	return nil
}

// RemoveVirtualRule deletes an active virtual-patch rule (e.g. once upstream CVE is patched).
func (e *Engine) RemoveVirtualRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.virtualRules[id]; !ok {
		return false
	}
	delete(e.virtualRules, id)
	return true
}

// PruneExpiredVirtualRules removes all virtual rules whose TTL has elapsed and returns their IDs.
func (e *Engine) PruneExpiredVirtualRules(now time.Time) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var pruned []string
	for id, entry := range e.virtualRules {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			delete(e.virtualRules, id)
			pruned = append(pruned, id)
		}
	}
	sort.Strings(pruned)
	return pruned
}

// VirtualRules returns a sorted snapshot of all non-expired virtual-patch rules.
func (e *Engine) VirtualRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]Rule, 0, len(e.virtualRules))
	for _, entry := range e.virtualRules {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			continue
		}
		out = append(out, entry.rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AddRuntimeAllow adds a strictly scoped exception bound to full canonical exe path + target path.
func (e *Engine) AddRuntimeAllow(ruleID, exe, path string) {
	if ruleID == "" || exe == "" || path == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runtimeAllow = append(e.runtimeAllow, allowEntry{
		ruleID: ruleID,
		exe:    cleanSlash(exe),
		path:   cleanSlash(path),
	})
}

func (e *Engine) isRuntimeAllowed(ruleID string, ev model.Event) bool {
	if ev.Exe == "" || ev.Path == "" {
		return false
	}
	exe := cleanSlash(ev.Exe)
	p := cleanSlash(ev.Path)
	for _, a := range e.runtimeAllow {
		if a.ruleID == ruleID && a.exe == exe && a.path == p {
			return true
		}
	}
	return false
}

// Evaluate checks an event against all deterministic policies.
func (e *Engine) Evaluate(ev model.Event) ([]model.PolicyMatch, model.Action, model.Severity) {
	// Normalize paths defensively even if Evaluate is called directly without lineage.Enrich.
	if ev.Path != "" {
		ev.Path = cleanSlash(ev.Path)
	}
	if ev.Exe != "" {
		ev.Exe = cleanSlash(ev.Exe)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []model.PolicyMatch
	action := model.ActionAllow
	severity := model.SeverityInfo

	now := time.Now().UTC()
	evalOne := func(r *Rule) {
		if !matchesRule(r, ev) {
			return
		}
		if e.isRuntimeAllowed(r.ID, ev) {
			return
		}
		matches = append(matches, model.PolicyMatch{
			RuleID:      r.ID,
			RuleName:    r.Name,
			Category:    r.Category,
			Severity:    r.Severity,
			Action:      r.Action,
			Description: r.Description,
			MITRE:       r.MITRE,
		})
		action = model.MaxAction(action, r.Action)
		if r.Severity.Rank() > severity.Rank() {
			severity = r.Severity
		}
	}

	for i := range e.rules {
		evalOne(&e.rules[i])
	}
	for _, ve := range e.virtualRules {
		if !ve.expiresAt.IsZero() && !now.Before(ve.expiresAt) {
			continue
		}
		r := ve.rule
		evalOne(&r)
	}

	return matches, action, severity
}

func matchesRule(r *Rule, ev model.Event) bool {
	m := &r.Match

	if len(m.EventTypes) > 0 {
		ok := false
		for _, et := range m.EventTypes {
			if et == ev.Type || (ev.Simulated && et == model.EventSimulated) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	// Security invariant: exclusions ONLY match exact canonical full executable paths
	// (never attacker-controllable comm / PR_SET_NAME or basename like /tmp/ssh).
	if len(m.ExcludeExePaths) > 0 && ev.Exe != "" {
		for _, allowedExe := range m.ExcludeExePaths {
			if ev.Exe == cleanSlash(allowedExe) {
				return false
			}
		}
	}

	// Exact canonical executable match (used by zero-day virtual patches to contain vulnerable binaries).
	if len(m.ExePaths) > 0 {
		ok := false
		for _, targetExe := range m.ExePaths {
			if ev.Exe != "" && ev.Exe == cleanSlash(targetExe) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	commLower := strings.ToLower(ev.Comm)
	exeBase := strings.ToLower(filepath.Base(ev.Exe))

	if len(m.CommIn) > 0 {
		ok := false
		for _, c := range m.CommIn {
			cL := strings.ToLower(c)
			if commLower == cL || exeBase == cL {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	if m.RequireWrite && !ev.IsWrite {
		return false
	}

	for _, exGlob := range m.ExcludePathGlobs {
		if matchGlob(exGlob, ev.Path) {
			return false
		}
	}

	if len(m.PathGlobs) > 0 {
		ok := false
		for _, g := range m.PathGlobs {
			if matchGlob(g, ev.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	if m.DestructiveRM {
		if !IsDestructiveRM(ev) {
			return false
		}
	}

	if len(r.compiledCmdRegex) > 0 {
		var targets []string
		if ev.Cmdline != "" {
			targets = append(targets, ev.Cmdline)
		}
		if ev.ProcCmdline != "" && ev.ProcCmdline != ev.Cmdline {
			targets = append(targets, ev.ProcCmdline)
		}
		if len(targets) == 0 && ev.Path != "" {
			targets = append(targets, ev.Path)
		}
		ok := false
		for _, re := range r.compiledCmdRegex {
			for _, target := range targets {
				if re.MatchString(target) {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}

	if len(m.AncestorAny) > 0 {
		if !matchesAnyAncestor(m.AncestorAny, ev) {
			return false
		}
	}

	if len(m.DstPorts) > 0 {
		ok := false
		for _, p := range m.DstPorts {
			if ev.DstPort == p {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	if m.DstIPNotPrivate {
		if ev.DstIP == "" || !isPublicIP(ev.DstIP) {
			return false
		}
	}

	return true
}

// IsDestructiveRM parses tokenized argv (plus kernel Cmdline and /proc/<pid>/cmdline when argv > 8)
// to detect recursive rm targeting critical system roots or a user's home root, including
// GNU abbreviations (--r, --rec), --, -Rf, /bin/rm, and relative targets resolved against ev.Cwd.
func IsDestructiveRM(ev model.Event) bool {
	checkShellScript := func(script, cwd string) bool {
		// Split simple shell command chains on &&, ||, ; so `cd / && rm -r usr` tracks cwd.
		normalized := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n").Replace(script)
		curCwd := cwd
		for _, part := range strings.Split(normalized, "\n") {
			fields := strings.Fields(part)
			if len(fields) == 0 {
				continue
			}
			if fields[0] == "cd" && len(fields) >= 2 {
				dest := fields[1]
				if strings.HasPrefix(filepath.ToSlash(dest), "/") {
					curCwd = cleanSlash(dest)
				} else if curCwd != "" {
					curCwd = cleanSlash(strings.TrimRight(filepath.ToSlash(curCwd), "/") + "/" + dest)
				}
				continue
			}
			if checkRMTokens(fields, "", curCwd) {
				return true
			}
		}
		return false
	}

	checkSlice := func(tokens []string, exe, cwd string) bool {
		if len(tokens) == 0 {
			return false
		}
		if checkRMTokens(tokens, exe, cwd) {
			return true
		}
		for i := 0; i < len(tokens)-1; i++ {
			if tokens[i] == "-c" || tokens[i] == "-lc" {
				// Quoted single-arg shell command (preserved in eBPF argv).
				if checkShellScript(tokens[i+1], cwd) {
					return true
				}
				// Space-split cmdline fallback.
				if checkShellScript(strings.Join(tokens[i+1:], " "), cwd) {
					return true
				}
			}
		}
		return false
	}

	if checkSlice(ev.Argv, ev.Exe, ev.Cwd) {
		return true
	}
	if ev.Cmdline != "" && checkSlice(strings.Fields(ev.Cmdline), ev.Exe, ev.Cwd) {
		return true
	}
	if ev.ProcCmdline != "" && ev.ProcCmdline != ev.Cmdline && checkSlice(strings.Fields(ev.ProcCmdline), ev.Exe, ev.Cwd) {
		return true
	}
	return false
}

func checkRMTokens(tokens []string, exe, cwd string) bool {
	if len(tokens) < 2 {
		return false
	}
	prog := strings.ToLower(filepath.Base(filepath.ToSlash(tokens[0])))
	exeBase := strings.ToLower(filepath.Base(filepath.ToSlash(exe)))
	if prog != "rm" && exeBase != "rm" {
		return false
	}

	recursive := false
	endOfOpts := false
	var targets []string

	for _, tok := range tokens[1:] {
		if tok == "#" || strings.HasPrefix(tok, "#") {
			break
		}
		if !endOfOpts && tok == "--" {
			endOfOpts = true
			continue
		}
		if !endOfOpts && strings.HasPrefix(tok, "--") {
			// Support all GNU option abbreviations (--r, --re, --rec, --recursive).
			if len(tok) >= 3 && strings.HasPrefix("--recursive", tok) {
				recursive = true
			}
			continue
		}
		if !endOfOpts && strings.HasPrefix(tok, "-") && len(tok) > 1 {
			for _, ch := range tok[1:] {
				if ch == 'r' || ch == 'R' {
					recursive = true
				}
			}
			continue
		}
		targets = append(targets, tok)
	}

	if !recursive {
		return false
	}

	exactDangerous := map[string]bool{
		"/": true, "/*": true, "~": true, "~/*": true, "$HOME": true, "${HOME}": true,
	}
	criticalPrefixes := []string{
		"/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root",
	}

	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}
		if exactDangerous[raw] {
			return true
		}
		candidate := raw
		if !strings.HasPrefix(filepath.ToSlash(candidate), "/") && !strings.HasPrefix(candidate, "~") && !strings.HasPrefix(candidate, "$") {
			if cwd != "" {
				candidate = strings.TrimRight(filepath.ToSlash(cwd), "/") + "/" + candidate
			}
		}
		cleaned := cleanSlash(candidate)
		if exactDangerous[cleaned] {
			return true
		}
		for _, pref := range criticalPrefixes {
			if cleaned == pref || strings.HasPrefix(cleaned, pref+"/") {
				// Allow harmless /var/tmp/* cleanup; protect everything else under /var, /etc, /usr, etc.
				if strings.HasPrefix(cleaned, "/var/tmp/") {
					continue
				}
				return true
			}
		}
		// Protect /home and top-level /home/<user> (shell expands ~ before execve),
		// while still allowing deep project build-dir cleanup like /home/alice/proj/dist.
		if cleaned == "/home" || cleaned == "/home/*" {
			return true
		}
		if strings.HasPrefix(cleaned, "/home/") {
			rest := strings.TrimPrefix(cleaned, "/home/")
			if rest != "" && !strings.Contains(rest, "/") {
				return true
			}
		}
	}
	return false
}

func matchesAnyAncestor(needles []string, ev model.Event) bool {
	check := func(comm, exe, cmdline string) bool {
		cL := strings.ToLower(comm)
		eL := strings.ToLower(filepath.Base(exe))
		cmdL := strings.ToLower(cmdline)
		for _, n := range needles {
			nL := strings.ToLower(n)
			if cL == nL || eL == nL || strings.Contains(cL, nL) || strings.Contains(cmdL, nL) {
				return true
			}
		}
		return false
	}
	for _, anc := range ev.Ancestry {
		if check(anc.Comm, anc.Exe, anc.Cmdline) {
			return true
		}
	}
	return false
}

func isPublicIP(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return true
}

func cleanSlash(p string) string {
	p = filepath.ToSlash(p)
	isAbs := strings.HasPrefix(p, "/")
	parts := strings.Split(p, "/")
	stack := make([]string, 0, len(parts))
	for _, seg := range parts {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 && stack[len(stack)-1] != ".." {
				stack = stack[:len(stack)-1]
			} else if !isAbs {
				stack = append(stack, "..")
			}
		default:
			stack = append(stack, seg)
		}
	}
	joined := strings.Join(stack, "/")
	if isAbs {
		return "/" + joined
	}
	if joined == "" {
		return "."
	}
	return joined
}

func matchGlob(pattern, value string) bool {
	if pattern == "" || value == "" {
		return false
	}
	normPat := filepath.ToSlash(pattern)
	normVal := filepath.ToSlash(value)
	return matchSegments(strings.Split(normPat, "/"), strings.Split(normVal, "/"))
}

func matchSegments(pat, val []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(val); i++ {
				if matchSegments(pat, val[i:]) {
					return true
				}
			}
			return false
		}
		if len(val) == 0 {
			return false
		}
		matched, err := filepath.Match(pat[0], val[0])
		if err != nil || !matched {
			return false
		}
		pat = pat[1:]
		val = val[1:]
	}
	return len(val) == 0
}
