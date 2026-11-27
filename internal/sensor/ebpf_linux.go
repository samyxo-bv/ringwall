// SPDX-License-Identifier: Apache-2.0
//go:build linux

package sensor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

// bpfFileKey matches struct file_key in ebpf/ringwall.bpf.c byte-for-byte.
type bpfFileKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

type ebpfSensor struct {
	coll           *ebpf.Collection
	links          []link.Link
	reader         *ringbuf.Reader
	configMap      *ebpf.Map
	statsMap       *ebpf.Map
	denyExecMap    *ebpf.Map
	openHook       string
	lsmAttached    bool
	lsmEnforce     atomic.Bool
	execMapMu      sync.Mutex
	pinnedExecKeys map[bpfFileKey]struct{}
	chanDrops      atomic.Uint64
}

func bpfLSMAvailable() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, tok := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if strings.TrimSpace(tok) == "bpf" {
			return true
		}
	}
	return false
}

// fileKeysForPath returns kernel (s_dev, i_ino) identifiers for path, including parent-dir s_dev
// so overlayfs lower-layer files match both their lower dev and overlayfs superblock s_dev.
func fileKeysForPath(p string) []bpfFileKey {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return nil
	}
	toKernelDev := func(rawDev uint64) uint32 {
		return uint32((unix.Major(rawDev) << 20) | (unix.Minor(rawDev) & 0xfffff))
	}
	primary := bpfFileKey{Ino: st.Ino, Dev: toKernelDev(uint64(st.Dev))}
	keys := []bpfFileKey{primary}

	if dirInfo, derr := os.Stat(filepath.Dir(p)); derr == nil {
		if dst, ok := dirInfo.Sys().(*syscall.Stat_t); ok {
			ddev := toKernelDev(uint64(dst.Dev))
			if ddev != primary.Dev {
				keys = append(keys, bpfFileKey{Ino: st.Ino, Dev: ddev})
			}
		}
	}
	return keys
}

func populateAllowedSSHExes(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	candidates := []string{
		"/usr/bin/ssh",
		"/usr/bin/ssh-agent",
		"/usr/bin/ssh-add",
		"/usr/bin/ssh-keygen",
		"/bin/ssh",
	}
	val := uint32(1)
	added := 0
	for _, p := range candidates {
		for _, k := range fileKeysForPath(p) {
			if err := m.Put(&k, &val); err == nil {
				added++
			}
		}
	}
	return added
}

// populatePinnedSecretInodes pins existing SSH private key inodes into lsm_deny_file_inodes
// so even hardlinks or source-renames are blocked synchronously by lsm/file_open.
func populatePinnedSecretInodes(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	patterns := []string{
		"/home/*/.ssh/id_*",
		"/home/*/.ssh/*.pem",
		"/home/*/.ssh/*.key",
		"/root/.ssh/id_*",
		"/root/.ssh/*.pem",
		"/root/.ssh/*.key",
	}
	val := uint32(1)
	added := 0
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, p := range matches {
			if strings.HasSuffix(p, ".pub") {
				continue
			}
			for _, k := range fileKeysForPath(p) {
				if err := m.Put(&k, &val); err == nil {
					added++
				}
			}
		}
	}
	return added
}

func newEBPFSensor(cfg config.SensorConfig) (Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var spec *ebpf.CollectionSpec
	var err error
	if len(embeddedBPF) > 0 {
		spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedBPF))
	} else if cfg.BPFObjectPath != "" {
		spec, err = ebpf.LoadCollectionSpec(cfg.BPFObjectPath)
	} else {
		return nil, errors.New("no embedded eBPF bytecode or bpf_object_path configured")
	}
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	lsmReady := bpfLSMAvailable()
	if !lsmReady {
		delete(spec.Programs, "trace_lsm_file_open")
		delete(spec.Programs, "trace_lsm_bprm_check")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil && (spec.Programs["trace_lsm_file_open"] != nil || spec.Programs["trace_lsm_bprm_check"] != nil) {
		log.Printf("ringwall: eBPF LSM programs failed to load (%v); retrying without LSM hooks", err)
		delete(spec.Programs, "trace_lsm_file_open")
		delete(spec.Programs, "trace_lsm_bprm_check")
		lsmReady = false
		coll, err = ebpf.NewCollection(spec)
	}
	if err != nil && spec.Programs["trace_security_file_open"] != nil {
		log.Printf("ringwall: fentry/security_file_open unavailable (%v); falling back to syscall open tracepoints", err)
		delete(spec.Programs, "trace_security_file_open")
		coll, err = ebpf.NewCollection(spec)
	}
	if err != nil {
		return nil, fmt.Errorf("load bpf collection: %w", err)
	}

	cleanup := func(links []link.Link) {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
	}

	cfgMap := coll.Maps["config_map"]
	if cfgMap != nil {
		key0 := uint32(0)
		selfPID := uint32(os.Getpid())
		if err := cfgMap.Put(&key0, &selfPID); err != nil {
			cleanup(nil)
			return nil, fmt.Errorf("set self pid in bpf config_map: %w", err)
		}
		key1 := uint32(1)
		enforceVal := uint32(0)
		if cfg.EnableLSMBlocking {
			enforceVal = 1
		}
		_ = cfgMap.Put(&key1, &enforceVal)
	}

	links := make([]link.Link, 0, 18)
	openHook := ""
	lsmOpenActive := false

	// Tier 1: Synchronous eBPF LSM pre-syscall blocking (when booted with lsm=...,bpf).
	if lsmReady {
		if prog := coll.Programs["trace_lsm_file_open"]; prog != nil {
			sshCount := populateAllowedSSHExes(coll.Maps["allowed_ssh_exe_inodes"])
			pinCount := populatePinnedSecretInodes(coll.Maps["lsm_deny_file_inodes"])
			l, attachErr := link.AttachLSM(link.LSMOptions{Program: prog})
			if attachErr != nil {
				log.Printf("ringwall: lsm/file_open attach failed (%v); falling back to fentry", attachErr)
			} else {
				links = append(links, l)
				lsmOpenActive = true
				openHook = "lsm/file_open"
				log.Printf("ringwall: attached lsm/file_open (synchronous pre-read kernel blocking active; enforce=%v allowed_ssh=%d pinned_secrets=%d)",
					cfg.EnableLSMBlocking, sshCount, pinCount)
			}
		}
		if prog := coll.Programs["trace_lsm_bprm_check"]; prog != nil {
			l, attachErr := link.AttachLSM(link.LSMOptions{Program: prog})
			if attachErr != nil {
				log.Printf("ringwall: optional lsm/bprm_check_security not attached: %v", attachErr)
			} else {
				links = append(links, l)
				log.Printf("ringwall: attached lsm/bprm_check_security (synchronous virtual-patch exec blocking active)")
			}
		}
	}

	// Tier 2: Kernel-resolved fentry/security_file_open (bpf_d_path) when LSM is not active.
	fentryOpenActive := false
	if !lsmOpenActive {
		if prog := coll.Programs["trace_security_file_open"]; prog != nil {
			l, attachErr := link.AttachTracing(link.TracingOptions{Program: prog})
			if attachErr != nil {
				log.Printf("ringwall: fentry/security_file_open attach failed (%v); falling back to syscall open tracepoints", attachErr)
			} else {
				links = append(links, l)
				fentryOpenActive = true
				openHook = "fentry/security_file_open"
				log.Printf("ringwall: attached fentry/security_file_open (kernel bpf_d_path canonicalization active)")
			}
		}
	}

	type tpSpec struct {
		prog     string
		group    string
		name     string
		optional bool
	}
	specs := []tpSpec{
		{prog: "trace_execve", group: "syscalls", name: "sys_enter_execve"},
		{prog: "trace_execveat", group: "syscalls", name: "sys_enter_execveat", optional: true},
		{prog: "trace_rename", group: "syscalls", name: "sys_enter_rename", optional: true},
		{prog: "trace_renameat", group: "syscalls", name: "sys_enter_renameat", optional: true},
		{prog: "trace_renameat2", group: "syscalls", name: "sys_enter_renameat2", optional: true},
		{prog: "trace_link", group: "syscalls", name: "sys_enter_link", optional: true},
		{prog: "trace_linkat", group: "syscalls", name: "sys_enter_linkat", optional: true},
		{prog: "trace_symlink", group: "syscalls", name: "sys_enter_symlink", optional: true},
		{prog: "trace_symlinkat", group: "syscalls", name: "sys_enter_symlinkat", optional: true},
		{prog: "trace_connect", group: "syscalls", name: "sys_enter_connect"},
		{prog: "trace_sendto", group: "syscalls", name: "sys_enter_sendto", optional: true},
		{prog: "trace_io_uring_setup", group: "syscalls", name: "sys_enter_io_uring_setup", optional: true},
	}
	// Tier 3: Raw syscall open tracepoints fallback.
	if !lsmOpenActive && !fentryOpenActive {
		openHook = "tracepoint/sys_enter_openat"
		specs = append(specs,
			tpSpec{prog: "trace_openat", group: "syscalls", name: "sys_enter_openat"},
			tpSpec{prog: "trace_openat2", group: "syscalls", name: "sys_enter_openat2", optional: true},
			tpSpec{prog: "trace_open", group: "syscalls", name: "sys_enter_open", optional: true},
			tpSpec{prog: "trace_creat", group: "syscalls", name: "sys_enter_creat", optional: true},
		)
	}

	for _, s := range specs {
		prog := coll.Programs[s.prog]
		if prog == nil {
			if s.optional {
				log.Printf("ringwall: optional bpf program %q absent", s.prog)
				continue
			}
			cleanup(links)
			return nil, fmt.Errorf("bpf program %q missing from object", s.prog)
		}
		l, err := link.Tracepoint(s.group, s.name, prog, nil)
		if err != nil {
			if s.optional {
				log.Printf("ringwall: optional tracepoint %s/%s not attached: %v", s.group, s.name, err)
				continue
			}
			cleanup(links)
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", s.group, s.name, err)
		}
		links = append(links, l)
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		cleanup(links)
		return nil, errors.New("bpf ringbuf map 'events' missing")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		cleanup(links)
		return nil, fmt.Errorf("open bpf ringbuf: %w", err)
	}

	s := &ebpfSensor{
		coll:           coll,
		links:          links,
		reader:         rd,
		configMap:      cfgMap,
		statsMap:       coll.Maps["stats_map"],
		denyExecMap:    coll.Maps["lsm_deny_exec_inodes"],
		openHook:       openHook,
		lsmAttached:    lsmOpenActive,
		pinnedExecKeys: make(map[bpfFileKey]struct{}),
	}
	s.lsmEnforce.Store(lsmOpenActive && cfg.EnableLSMBlocking)
	return s, nil
}

func (s *ebpfSensor) Mode() string           { return "ebpf" }
func (s *ebpfSensor) OpenHook() string       { return s.openHook }
func (s *ebpfSensor) LSMEnforceActive() bool { return s.lsmAttached && s.lsmEnforce.Load() }

// SetLSMEnforce toggles synchronous -EPERM kernel blocking dynamically (e.g. off in audit mode, on in interactive/strict).
func (s *ebpfSensor) SetLSMEnforce(enabled bool) error {
	if s.configMap == nil {
		return nil
	}
	key := uint32(1)
	val := uint32(0)
	if enabled && s.lsmAttached {
		val = 1
	}
	if err := s.configMap.Put(&key, &val); err != nil {
		return err
	}
	s.lsmEnforce.Store(val == 1)
	return nil
}

// SyncBlockedExecPaths reconciles lsm_deny_exec_inodes with active zero-day virtual-patched executable paths.
func (s *ebpfSensor) SyncBlockedExecPaths(paths []string) (int, error) {
	if !s.lsmAttached || s.denyExecMap == nil {
		return 0, nil
	}
	s.execMapMu.Lock()
	defer s.execMapMu.Unlock()

	desired := make(map[bpfFileKey]struct{})
	for _, p := range paths {
		for _, k := range fileKeysForPath(p) {
			desired[k] = struct{}{}
		}
	}
	for old := range s.pinnedExecKeys {
		if _, keep := desired[old]; !keep {
			_ = s.denyExecMap.Delete(&old)
			delete(s.pinnedExecKeys, old)
		}
	}
	val := uint32(1)
	for k := range desired {
		if err := s.denyExecMap.Put(&k, &val); err == nil {
			s.pinnedExecKeys[k] = struct{}{}
		}
	}
	return len(s.pinnedExecKeys), nil
}

// Dropped returns the sum of kernel ringbuf reserve drops plus userspace channel drops.
func (s *ebpfSensor) Dropped() uint64 {
	total := s.chanDrops.Load()
	if s.statsMap != nil {
		key := uint32(0)
		var perCPU []uint64
		if err := s.statsMap.Lookup(&key, &perCPU); err == nil {
			for _, v := range perCPU {
				total += v
			}
		}
	}
	return total
}

func (s *ebpfSensor) Start(ctx context.Context, out chan<- model.Event) error {
	defer func() {
		_ = s.reader.Close()
		for _, l := range s.links {
			_ = l.Close()
		}
		s.coll.Close()
	}()

	go func() {
		<-ctx.Done()
		_ = s.reader.Close()
	}()

	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read bpf ringbuf: %w", err)
		}
		ev, err := DecodeRawEvent(rec.RawSample, time.Now())
		if err != nil {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		default:
			s.chanDrops.Add(1)
		}
	}
}
