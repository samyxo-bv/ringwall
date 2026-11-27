// SPDX-License-Identifier: Apache-2.0
package lineage

import (
	"sync"
	"testing"

	"github.com/samyxo-bv/ringwall/internal/model"
)

type fakeProcReader struct {
	procs    map[int]model.ProcessInfo
	fds      map[int]map[int32]string
	symlinks map[string]string
}

func (f *fakeProcReader) ReadProcess(pid int) (model.ProcessInfo, bool) {
	p, ok := f.procs[pid]
	return p, ok
}

func (f *fakeProcReader) ReadFDPath(pid int, fd int32) (string, bool) {
	if m, ok := f.fds[pid]; ok {
		p, exists := m[fd]
		return p, exists
	}
	return "", false
}

func (f *fakeProcReader) ReadLink(_ int, path string) (string, bool) {
	if s, ok := f.symlinks[path]; ok {
		return s, true
	}
	return "", false
}

func TestCanonicalizePathDefeatsAllBypasses(t *testing.T) {
	fr := &fakeProcReader{
		procs: map[int]model.ProcessInfo{
			100: {PID: 100, PPID: 50, StartTime: 12345, Comm: "cat", Exe: "/usr/bin/cat", Cwd: "/home/alice/.ssh"},
			50:  {PID: 50, PPID: 1, StartTime: 10000, Comm: "claude", Exe: "/usr/local/bin/claude"},
		},
		fds: map[int]map[int32]string{
			100: {7: "/home/alice/.ssh"},
		},
		symlinks: map[string]string{
			"/tmp/k": "/home/alice/.ssh/id_ed25519",
			"/tmp/d": "/home/alice/.ssh",
		},
	}
	tr := NewTracker(fr)

	cases := []struct {
		name  string
		path  string
		dirfd int32
		want  string
	}{
		{"proc self root traversal", "/proc/self/root/home/alice/.ssh/id_rsa", -100, "/home/alice/.ssh/id_rsa"},
		{"proc pid root traversal", "/proc/100/root/etc/shadow", -100, "/etc/shadow"},
		{"proc self cwd traversal", "/proc/self/cwd/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"dev fd traversal", "/dev/fd/7/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"proc self fd traversal", "/proc/self/fd/7/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"leading double slash", "//home/alice/.ssh/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"leading dot slash", "/./home/alice/.ssh/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"relative path via cwd", "id_rsa", -100, "/home/alice/.ssh/id_rsa"},
		{"relative path via openat dirfd", "id_ed25519", 7, "/home/alice/.ssh/id_ed25519"},
		{"leaf symlink bypass", "/tmp/k", -100, "/home/alice/.ssh/id_ed25519"},
		{"directory symlink bypass", "/tmp/d/id_ed25519", -100, "/home/alice/.ssh/id_ed25519"},
		{"double slash normalization", "/etc//shadow", -100, "/etc/shadow"},
		{"dot segment normalization", "/etc/./shadow", -100, "/etc/shadow"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{Type: model.EventOpen, PID: 100, Path: tc.path, DirFD: tc.dirfd}
			tr.Enrich(&ev)
			if ev.Path != tc.want {
				t.Fatalf("got %q, want %q", ev.Path, tc.want)
			}
			if ev.StartTime != 12345 {
				t.Fatalf("expected StartTime=12345, got %d", ev.StartTime)
			}
			if len(ev.Ancestry) != 1 || ev.Ancestry[0].Comm != "claude" {
				t.Fatalf("expected claude ancestry, got %+v", ev.Ancestry)
			}
		})
	}
}

func TestTrackerConcurrentEnrichAndCycleSafe(t *testing.T) {
	fr := &fakeProcReader{
		procs: map[int]model.ProcessInfo{
			10: {PID: 10, PPID: 20, Comm: "a"},
			20: {PID: 20, PPID: 10, Comm: "b"},
		},
	}
	tr := NewTracker(fr)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := model.Event{Type: model.EventExec, PID: 10, Path: "/usr/bin/id"}
			tr.Enrich(&ev)
			if len(ev.Ancestry) > 2 {
				t.Errorf("cycle guard failed: ancestry len %d", len(ev.Ancestry))
			}
		}()
	}
	wg.Wait()
}
