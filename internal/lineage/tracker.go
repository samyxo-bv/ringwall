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

var (
	procRootPrefixRe = regexp.MustCompile(`^/proc/(?:self|thread-self|[0-9]+)/root(/|$)`)
	procCwdPrefixRe  = regexp.MustCompile(`^/proc/(?:self|thread-self|[0-9]+)/cwd(/|$)`)
	procFDPrefixRe   = regexp.MustCompile(`^(?:/proc/(?:self|thread-self|[0-9]+)/fd|/dev/fd)/([0-9]+)(/|$)`)
)

// ProcReader abstracts /proc lookups for testability.
type ProcReader interface {
	ReadProcess(pid int) (model.ProcessInfo, bool)
	ReadFDPath(pid int, fd int32) (string, bool)
	ReadLink(pid int, path string) (string, bool)
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

// ReadLink inspects a single path component inside the target PID's mount namespace via /proc/<pid>/root,
// defeating PrivateTmp=yes and container mount namespace isolation.
func (linuxProcReader) ReadLink(pid int, path string) (string, bool) {
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	if pid > 0 {
		if target, err := os.Readlink(fmt.Sprintf("/proc/%d/root%s", pid, path)); err == nil {
			return target, true
		}
	}
	if target, err := os.Readlink(path); err == nil {
		return target, true
	}
	return "", false
}

// ResolveSymlinksComponentWise walks every prefix of path left-to-right (up to 16 symlink hops),
// catching both leaf symlinks (/tmp/k) and directory symlinks (ln -s ~/.ssh /tmp/d; cat /tmp/d/id_ed25519).
func ResolveSymlinksComponentWise(path string, readlink func(string) (string, bool)) string {
	if readlink == nil || !strings.HasPrefix(path, "/") {
		return path
	}
	cur := cleanSlashPath(path)
	for hop := 0; hop < 16; hop++ {
		segs := strings.Split(strings.TrimPrefix(cur, "/"), "/")
		prefix := ""
		replaced := false
		for i, seg := range segs {
			if seg == "" {
				continue
			}
			prefix += "/" + seg
			target, ok := readlink(prefix)
			if !ok {
				continue
			}
			rest := strings.Join(segs[i+1:], "/")
			var next string
			if strings.HasPrefix(target, "/") {
				next = target
			} else {
				parent := prefix[:strings.LastIndexByte(prefix, '/')]
				if parent == "" {
					parent = "/"
				}
				next = parent + "/" + target
			}
			if rest != "" {
				next = strings.TrimRight(next, "/") + "/" + rest
			}
			cur = cleanSlashPath(next)
			replaced = true
			break
		}
		if !replaced {
			break
		}
	}
	return cur
}

func ParseProcStat(stat string) (comm string, ppid int, startTime uint64) {
	openIdx := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(stat) {
		return "", 0, 0
	}
	comm = stat[openIdx+1 : closeIdx]
	rest := strings.Fields(stat[closeIdx+2:])
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

// CanonicalizePath normalizes //home, /./home, /proc/<pid|self>/(root|cwd|fd), /dev/fd/<n>,
// relative paths (via dirfd or cwd), and component-wise directory/file symlinks.
func CanonicalizePath(rawPath string, dirfd int32, cwd string, fdResolver func(int32) (string, bool), readlink func(string) (string, bool)) string {
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

	// Expand /proc/<pid|self>/(root|cwd|fd) and /dev/fd/<n> prefixes (up to 4 nested passes).
	for i := 0; i < 4; i++ {
		changed := false
		if procRootPrefixRe.MatchString(p) {
			p = cleanSlashPath(procRootPrefixRe.ReplaceAllString(p, "/"))
			changed = true
		}
		if cwd != "" && procCwdPrefixRe.MatchString(p) {
			base := strings.TrimRight(filepath.ToSlash(cwd), "/")
			p = cleanSlashPath(procCwdPrefixRe.ReplaceAllString(p, base+"/"))
			changed = true
		}
		if fdResolver != nil {
			if m := procFDPrefixRe.FindStringSubmatchIndex(p); m != nil {
				fdNumStr := p[m[2]:m[3]]
				if fdNum, err := strconv.Atoi(fdNumStr); err == nil {
					if resolvedDir, ok := fdResolver(int32(fdNum)); ok {
						rest := p[m[1]:]
						base := strings.TrimRight(filepath.ToSlash(resolvedDir), "/")
						if rest != "" {
							p = cleanSlashPath(base + "/" + rest)
						} else {
							p = cleanSlashPath(base)
						}
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	if readlink != nil && strings.HasPrefix(p, "/") {
		p = ResolveSymlinksComponentWise(p, readlink)
		for i := 0; i < 2; i++ {
			if procRootPrefixRe.MatchString(p) {
				p = cleanSlashPath(procRootPrefixRe.ReplaceAllString(p, "/"))
			}
		}
	}

	return p
}

func cleanSlashPath(p string) string {
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
		if ev.Cwd == "" && cwd != "" {
			ev.Cwd = cwd
		}
		if ev.Exe == "" {
			ev.Exe = live.Exe
		}
		// Keep kernel-captured eBPF Cmdline intact to avoid /proc/cmdline TOCTOU/overwrite,
		// while retaining fuller /proc/<pid>/cmdline (e.g. > 8 args) separately in ProcCmdline.
		if live.Cmdline != "" {
			if ev.Cmdline == "" {
				ev.Cmdline = live.Cmdline
			} else if live.Cmdline != ev.Cmdline {
				ev.ProcCmdline = live.Cmdline
			}
		}
		if ev.UID == 0 && live.UID != 0 {
			ev.UID = live.UID
		}
	}

	rl := func(p string) (string, bool) { return t.reader.ReadLink(ev.PID, p) }
	if ev.Path != "" {
		ev.RawPath = ev.Path
		ev.Path = CanonicalizePath(
			ev.Path,
			ev.DirFD,
			cwd,
			func(fd int32) (string, bool) { return t.reader.ReadFDPath(ev.PID, fd) },
			rl,
		)
	}
	if ev.Exe != "" {
		ev.Exe = CanonicalizePath(ev.Exe, atFDCWD, cwd, nil, rl)
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
