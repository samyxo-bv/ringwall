// SPDX-License-Identifier: Apache-2.0
package lineage

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/samyxo-bv/ringwall/internal/model"
)

const (
	maxCacheEntries = 4096
	maxAncestryWalk = 16
)

// ProcReader abstracts /proc lookups for testability.
type ProcReader interface {
	ReadProcess(pid int) (model.ProcessInfo, bool)
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

	comm, ppid := parseProcStat(string(statBytes))
	info := model.ProcessInfo{
		PID:  pid,
		PPID: ppid,
		Comm: comm,
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
		info.Exe = exe
	}
	if cwd, err := os.Readlink(base + "/cwd"); err == nil {
		info.Cwd = cwd
	}
	if statusBytes, err := os.ReadFile(base + "/status"); err == nil {
		info.UID = parseUIDFromStatus(string(statusBytes))
	}
	return info, true
}

func parseProcStat(stat string) (comm string, ppid int) {
	openIdx := strings.IndexByte(stat, '(')
	closeIdx := strings.LastIndexByte(stat, ')')
	if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(stat) {
		return "", 0
	}
	comm = stat[openIdx+1 : closeIdx]
	rest := strings.Fields(stat[closeIdx+2:])
	// rest[0] is state, rest[1] is ppid
	if len(rest) >= 2 {
		ppid, _ = strconv.Atoi(rest[1])
	}
	return comm, ppid
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

// Tracker resolves process details and full ancestor chains with an in-memory cache
// so short-lived child processes still preserve their ancestry.
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

// Enrich populates missing process metadata and the ancestor chain on an event.
func (t *Tracker) Enrich(ev *model.Event) {
	if ev == nil || ev.PID <= 0 {
		return
	}

	if live, ok := t.lookup(ev.PID); ok {
		if ev.PPID == 0 {
			ev.PPID = live.PPID
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

	// Store latest known info for this PID so descendants can trace back to it.
	t.Record(model.ProcessInfo{
		PID:     ev.PID,
		PPID:    ev.PPID,
		UID:     ev.UID,
		Comm:    ev.Comm,
		Exe:     ev.Exe,
		Cmdline: ev.Cmdline,
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
