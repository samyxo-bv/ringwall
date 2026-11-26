// SPDX-License-Identifier: Apache-2.0
package lineage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/samyxo-bv/ringwall/internal/model"
)

const (
	maxCacheEntries = 4096
	maxAncestryWalk = 16
	atFDCWD         = -100
)

var procRootPrefixRe = regexp.MustCompile(`^/proc/(?:self|thread-self|[0-9]+)/root(/|$)`)

// ProcReader abstracts /proc lookups for testability.
type ProcReader interface {
	ReadProcess(pid int) (model.ProcessInfo, bool)
	ReadFDPath(pid int, fd int32) (string, bool)
	EvalSymlinks(pid int, path string) string
}

type linuxProcReader struct{}

func (linuxProcReader) ReadProcess(pid int) (model.ProcessInfo, bool) {
	if pid <= 0 {
		return model.ProcessInfo{}, false
	}
	base := fmt.Sprintf("/proc/%d", pid)
	statBytes, err := os.ReadFile(base + "/stat")
	if err != nil {
		return model.ProcessInfo{}, false
	}

	comm, ppid, startTime := ParseProcStat(string(statBytes))
	info := model.ProcessInfo{
		PID:       pid,
		PPID:      ppid,
		StartTime: startTime,
		Comm:      comm,
	}

	if cmdBytes, err := os.ReadFile(base + "/cmdline"); err == nil && len(cmdBytes) > 0 {
		parts := bytes.Split(bytes.TrimRight(cmdBytes, "\x00"), []byte{0})
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if len(p) > 0 {
				out = append(out, string(p))
			}
		}
		info.Cmdline = strings.Join(out, " ")
	}
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		info.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cwd, err := os.Readlink(base + "/cwd"); err == nil {
		info.Cwd = cwd
	}
	if statusBytes, err := os.ReadFile(base + "/status"); err == nil {
		info.UID = parseUIDFromStatus(string(statusBytes))
	}
	return info, true
}

func (linuxProcReader) ReadFDPath(pid int, fd int32) (string, bool) {
	if pid <= 0 || fd < 0 {
		return "", false
	}
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "", false
	}
	return p, true
}

func (linuxProcReader) EvalSymlinks(pid int, path string) string {
	// Resolve symlinks inside the target process's mount namespace via /proc/<pid>/root
	// so PrivateTmp=yes and container mount namespaces never hide /tmp/* symlinks.
	if pid > 0 && strings.HasPrefix(path, "/") {
		cur := cleanSlashPath(path)
		for hop := 0; hop < 8; hop++ {
			target, err := os.Readlink(fmt.Sprintf("/proc/%d/root%s", pid, cur))
			if err != nil {
				break
			}
			if strings.HasPrefix(target, "/") {
				cur = cleanSlashPath(target)
			} else {
				dir := cur[:strings.LastIndexByte(cur, '/')]
				if dir == "" {
					dir = "/"
				}
				cur = cleanSlashPath(dir + "/" + target)
			}
		}
		if cur != cleanSlashPath(path) {
			return cur
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

// ParseProcStat parses comm, ppid, and starttime (field 22) from /proc/<pid>/stat.
func ParseProcStat(stat string) (comm string, ppid int, startTime uint64) {
	openIdx := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(stat) {
		return "", 0, 0
	}
	comm = stat[openIdx+1 : closeIdx]
	rest := strings.Fields(stat[closeIdx+2:])
	// rest[0] is field 3 (state), rest[1] is field 4 (ppid), rest[19] is field 22 (starttime).
	if len(rest) >= 2 {
		ppid, _ = strconv.Atoi(rest[1])
	}
	if len(rest) >= 20 {
		startTime, _ = strconv.ParseUint(rest[19], 10, 64)
	}
	return comm, ppid, startTime
}

func parseUIDFromStatus(status string) uint32 {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					return uint32(v)
				}
			}
		}
	}
	return 0
}

// ReadProcessStartTime reads field 22 (starttime) of /proc/<pid>/stat for PID-reuse verification.
func ReadProcessStartTime(pid int) (uint64, bool) {
	if pid <= 0 {
		return 0, false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	_, _, st := ParseProcStat(string(b))
	return st, st > 0
}

// CanonicalizePath normalizes /etc//shadow, /etc/./shadow, /proc/<pid|self>/root/...,
// relative paths (via dirfd or cwd), and symlinks so path-based policy bypasses cannot evade rules.
func CanonicalizePath(rawPath string, dirfd int32, cwd string, fdResolver func(int32) (string, bool), evalSymlinks func(string) string) string {
	if rawPath == "" {
		return ""
	}
	p := filepath.ToSlash(rawPath)

	if !strings.HasPrefix(p, "/") {
		base := ""
		if dirfd >= 0 && fdResolver != nil {
			if resolvedDir, ok := fdResolver(dirfd); ok {
				base = filepath.ToSlash(resolvedDir)
			}
		}
		if base == "" && cwd != "" {
			base = filepath.ToSlash(cwd)
		}
		if base != "" {
			p = strings.TrimRight(base, "/") + "/" + p
		}
	}

	p = cleanSlashPath(p)

	// Strip /proc/self/root/..., /proc/thread-self/root/..., or /proc/<pid>/root/... prefixes (repeatedly).
	for i := 0; i < 4; i++ {
		if !procRootPrefixRe.MatchString(p) {
			break
		}
		p = procRootPrefixRe.ReplaceAllString(p, "/")
		p = cleanSlashPath(p)
	}

	if evalSymlinks != nil && strings.HasPrefix(p, "/") {
		if sym := evalSymlinks(p); sym != "" {
			p = cleanSlashPath(filepath.ToSlash(sym))
			for i := 0; i < 2; i++ {
				if !procRootPrefixRe.MatchString(p) {
					break
				}
				p = procRootPrefixRe.ReplaceAllString(p, "/")
				p = cleanSlashPath(p)
			}
		}
	}

	return p
}

func cleanSlashPath(p string) string {
	// Manual POSIX clean so Windows unit tests also preserve leading '/' cleanly.
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

type Tracker struct {
	mu     sync.RWMutex
	cache  map[int]model.ProcessInfo
	order  []int
	reader ProcReader
}

func NewTracker(reader ProcReader) *Tracker {
	if reader == nil {
		reader = linuxProcReader{}
	}
	return &Tracker{
		cache:  make(map[int]model.ProcessInfo, 256),
		order:  make([]int, 0, 256),
		reader: reader,
	}
}

func (t *Tracker) Record(info model.ProcessInfo) {
	if info.PID <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.cache[info.PID]; !exists {
		if len(t.order) >= maxCacheEntries {
			evict := t.order[0]
			t.order = t.order[1:]
			delete(t.cache, evict)
		}
		t.order = append(t.order, info.PID)
	}
	t.cache[info.PID] = info
}

func (t *Tracker) lookup(pid int) (model.ProcessInfo, bool) {
	if live, ok := t.reader.ReadProcess(pid); ok {
		t.Record(live)
		return live, true
	}
	t.mu.RLock()
	cached, ok := t.cache[pid]
	t.mu.RUnlock()
	return cached, ok
}

// Enrich populates process metadata, start time, canonical file path, and full ancestry.
func (t *Tracker) Enrich(ev *model.Event) {
	if ev == nil || ev.PID <= 0 {
		return
	}

	var cwd string
	if live, ok := t.lookup(ev.PID); ok {
		cwd = live.Cwd
		if ev.PPID == 0 {
			ev.PPID = live.PPID
		}
		if ev.StartTime == 0 {
			ev.StartTime = live.StartTime
		}
		if ev.Comm == "" {
			ev.Comm = live.Comm
		}
		if ev.Exe == "" {
			ev.Exe = live.Exe
		}
		if ev.Cmdline == "" {
			ev.Cmdline = live.Cmdline
		}
		if ev.UID == 0 && live.UID != 0 {
			ev.UID = live.UID
		}
	}

	if ev.Path != "" {
		ev.RawPath = ev.Path
		ev.Path = CanonicalizePath(
			ev.Path,
			ev.DirFD,
			cwd,
			func(fd int32) (string, bool) { return t.reader.ReadFDPath(ev.PID, fd) },
			func(p string) string { return t.reader.EvalSymlinks(ev.PID, p) },
		)
	}
	if ev.Exe != "" {
		ev.Exe = CanonicalizePath(ev.Exe, atFDCWD, cwd, nil, func(p string) string { return t.reader.EvalSymlinks(ev.PID, p) })
	}

	t.Record(model.ProcessInfo{
		PID:       ev.PID,
		PPID:      ev.PPID,
		UID:       ev.UID,
		StartTime: ev.StartTime,
		Comm:      ev.Comm,
		Exe:       ev.Exe,
		Cmdline:   ev.Cmdline,
		Cwd:       cwd,
	})

	if len(ev.Ancestry) > 0 {
		return
	}

	seen := map[int]bool{ev.PID: true}
	cur := ev.PPID
	for depth := 0; depth < maxAncestryWalk && cur > 0 && !seen[cur]; depth++ {
		seen[cur] = true
		p, ok := t.lookup(cur)
		if !ok {
			break
		}
		ev.Ancestry = append(ev.Ancestry, p)
		if p.PPID <= 0 || p.PPID == cur {
			break
		}
		cur = p.PPID
	}
}
