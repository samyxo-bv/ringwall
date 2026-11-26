// SPDX-License-Identifier: Apache-2.0
//go:build linux

package sensor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

type ebpfSensor struct {
	coll      *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	statsMap  *ebpf.Map
	chanDrops atomic.Uint64
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

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load bpf collection: %w", err)
	}

	cleanup := func(links []link.Link) {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
	}

	if cfgMap, ok := coll.Maps["config_map"]; ok {
		key := uint32(0)
		selfPID := uint32(os.Getpid())
		if err := cfgMap.Put(&key, &selfPID); err != nil {
			cleanup(nil)
			return nil, fmt.Errorf("set self pid in bpf config_map: %w", err)
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
		{prog: "trace_openat", group: "syscalls", name: "sys_enter_openat"},
		{prog: "trace_openat2", group: "syscalls", name: "sys_enter_openat2", optional: true},
		{prog: "trace_open", group: "syscalls", name: "sys_enter_open", optional: true},
		{prog: "trace_connect", group: "syscalls", name: "sys_enter_connect"},
		{prog: "trace_sendto", group: "syscalls", name: "sys_enter_sendto", optional: true},
	}

	links := make([]link.Link, 0, len(specs))
	for _, s := range specs {
		prog := coll.Programs[s.prog]
		if prog == nil {
			if s.optional {
				continue
			}
			cleanup(links)
			return nil, fmt.Errorf("bpf program %q missing from object", s.prog)
		}
		l, err := link.Tracepoint(s.group, s.name, prog, nil)
		if err != nil {
			if s.optional {
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

	return &ebpfSensor{
		coll:     coll,
		links:    links,
		reader:   rd,
		statsMap: coll.Maps["stats_map"],
	}, nil
}

func (s *ebpfSensor) Mode() string { return "ebpf" }

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
