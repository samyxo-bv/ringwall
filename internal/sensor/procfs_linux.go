// SPDX-License-Identifier: Apache-2.0
//go:build linux

package sensor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

// procfsSensor is an automatic unprivileged fallback when CAP_BPF is unavailable.
type procfsSensor struct {
	interval time.Duration
	selfPID  int
}

func newProcfsSensor(cfg config.SensorConfig) (Sensor, error) {
	if _, err := os.Stat("/proc"); err != nil {
		return nil, fmt.Errorf("/proc unavailable: %w", err)
	}
	interval := time.Duration(cfg.PollIntervalMS) * time.Millisecond
	if interval < 50*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	return &procfsSensor{
		interval: interval,
		selfPID:  os.Getpid(),
	}, nil
}

func (p *procfsSensor) Mode() string { return "procfs-fallback" }

func (p *procfsSensor) Start(ctx context.Context, out chan<- model.Event) error {
	seen := make(map[int]string, 256)
	// Seed existing processes so startup doesn't flood alerts on preexisting daemons.
	p.scan(seen, nil)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.scan(seen, out)
		}
	}
}

func (p *procfsSensor) scan(seen map[int]string, out chan<- model.Event) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	active := make(map[int]bool, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == p.selfPID {
			continue
		}
		active[pid] = true

		cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(cmdBytes) == 0 {
			continue
		}
		parts := bytes.Split(bytes.TrimRight(cmdBytes, "\x00"), []byte{0})
		args := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) > 0 {
				args = append(args, string(part))
			}
		}
		cmdline := strings.Join(args, " ")
		if prev, ok := seen[pid]; ok && prev == cmdline {
			continue
		}
		seen[pid] = cmdline
		if out == nil {
			continue
		}

		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		comm := strings.TrimSpace(string(commBytes))

		ev := model.Event{
			Timestamp: time.Now().UTC(),
			Type:      model.EventExec,
			PID:       pid,
			Comm:      comm,
			Exe:       exe,
			Path:      exe,
			Cmdline:   cmdline,
		}
		select {
		case out <- ev:
		default:
		}
	}
	for pid := range seen {
		if !active[pid] {
			delete(seen, pid)
		}
	}
}
