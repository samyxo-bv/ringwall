// SPDX-License-Identifier: Apache-2.0
package enforcer

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

var safeNFTTableRe = regexp.MustCompile(`^[a-zA-Z0-9_]+ [a-zA-Z0-9_]+$`)

// Signaler abstracts OS process signaling for unit testing.
type Signaler interface {
	Signal(pid int, sig syscall.Signal) error
}

type osSignaler struct{}

func (osSignaler) Signal(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// Firewall abstracts nftables IP blocking.
type Firewall interface {
	BlockIP(ip netip.Addr) error
}

type nftFirewall struct {
	table string
}

func (f nftFirewall) BlockIP(ip netip.Addr) error {
	if !safeNFTTableRe.MatchString(f.table) {
		return fmt.Errorf("unsafe nft_table name %q", f.table)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return fmt.Errorf("refusing to block loopback/unspecified address %s", ip)
	}
	parts := strings.Fields(f.table)
	family, table := parts[0], parts[1]
	setName := "blocked_v4"
	if ip.Is6() {
		setName = "blocked_v6"
	}
	// Strict argv invocation — zero shell interpolation.
	cmd := exec.Command("nft", "add", "element", family, table, setName, fmt.Sprintf("{ %s }", ip.String()))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft block %s: %w (%s)", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}

type Enforcer struct {
	mode     config.Mode
	cfg      config.EnforcerConfig
	signaler Signaler
	firewall Firewall
	selfPID  int
	parentID int
}

func New(mode config.Mode, cfg config.EnforcerConfig, sig Signaler, fw Firewall) *Enforcer {
	if sig == nil {
		sig = osSignaler{}
	}
	if fw == nil {
		fw = nftFirewall{table: cfg.NFTTable}
	}
	return &Enforcer{
		mode:     mode,
		cfg:      cfg,
		signaler: sig,
		firewall: fw,
		selfPID:  os.Getpid(),
		parentID: os.Getppid(),
	}
}

func (e *Enforcer) isProtectedPID(pid int) bool {
	return pid <= 1 || pid == e.selfPID || pid == e.parentID
}

// Apply enforces a deterministic or escalated action according to the daemon mode.
func (e *Enforcer) Apply(ev model.Event, action model.Action) (model.IncidentStatus, string) {
	if action == model.ActionAllow || action == model.ActionWarn {
		return model.StatusOpen, "logged only"
	}
	if ev.Simulated {
		switch action {
		case model.ActionKill:
			if e.mode == config.ModeStrict {
				return model.StatusKilled, "simulated strict enforcement: process would receive SIGKILL"
			}
			return model.StatusFrozen, "simulated interactive enforcement: process frozen via SIGSTOP awaiting approval"
		case model.ActionBlockEgress:
			return model.StatusBlocked, fmt.Sprintf("simulated egress block for %s and SIGSTOP", ev.DstIP)
		default:
			return model.StatusFrozen, "simulated enforcement: process frozen via SIGSTOP"
		}
	}
	if e.mode == config.ModeAudit || e.cfg.DryRun {
		return model.StatusOpen, fmt.Sprintf("audit/dry-run mode: would execute %s on pid %d", action, ev.PID)
	}
	if e.isProtectedPID(ev.PID) {
		return model.StatusOpen, fmt.Sprintf("protected pid %d: signal skipped", ev.PID)
	}

	switch action {
	case model.ActionFreeze:
		if !e.cfg.EnableSignals {
			return model.StatusOpen, "signals disabled in config"
		}
		if err := e.signaler.Signal(ev.PID, syscall.SIGSTOP); err != nil {
			return model.StatusOpen, fmt.Sprintf("SIGSTOP failed for pid %d: %v", ev.PID, err)
		}
		return model.StatusFrozen, fmt.Sprintf("process %d frozen with SIGSTOP", ev.PID)

	case model.ActionBlockEgress:
		var notes []string
		status := model.StatusOpen
		if e.cfg.EnableSignals {
			if err := e.signaler.Signal(ev.PID, syscall.SIGSTOP); err == nil {
				status = model.StatusFrozen
				notes = append(notes, fmt.Sprintf("pid %d frozen (SIGSTOP)", ev.PID))
			} else {
				notes = append(notes, fmt.Sprintf("SIGSTOP failed: %v", err))
			}
		}
		if e.cfg.EnableNFTables && ev.DstIP != "" {
			if ip, err := netip.ParseAddr(ev.DstIP); err == nil {
				if err := e.firewall.BlockIP(ip); err == nil {
					status = model.StatusBlocked
					notes = append(notes, fmt.Sprintf("blocked egress %s in nftables", ip))
				} else {
					notes = append(notes, fmt.Sprintf("nftables block failed: %v", err))
				}
			}
		}
		if len(notes) == 0 {
			return status, "block_egress requested (signals/nftables disabled)"
		}
		return status, strings.Join(notes, "; ")

	case model.ActionKill:
		if !e.cfg.EnableSignals {
			return model.StatusOpen, "signals disabled in config"
		}
		// In interactive mode, freeze first so an operator can confirm kill vs resume.
		if e.mode == config.ModeInteractive {
			if err := e.signaler.Signal(ev.PID, syscall.SIGSTOP); err != nil {
				return model.StatusOpen, fmt.Sprintf("SIGSTOP failed for pid %d: %v", ev.PID, err)
			}
			return model.StatusFrozen, fmt.Sprintf("interactive mode: pid %d frozen (SIGSTOP) pending kill/resume", ev.PID)
		}
		if err := e.signaler.Signal(ev.PID, syscall.SIGKILL); err != nil {
			return model.StatusOpen, fmt.Sprintf("SIGKILL failed for pid %d: %v", ev.PID, err)
		}
		return model.StatusKilled, fmt.Sprintf("strict mode: pid %d terminated (SIGKILL)", ev.PID)
	}

	return model.StatusOpen, "no enforcement action"
}

func (e *Enforcer) Resume(pid int, simulated bool) error {
	if simulated || e.cfg.DryRun {
		return nil
	}
	if e.isProtectedPID(pid) {
		return fmt.Errorf("protected pid %d", pid)
	}
	if !e.cfg.EnableSignals {
		return nil
	}
	return e.signaler.Signal(pid, syscall.SIGCONT)
}

func (e *Enforcer) Kill(pid int, simulated bool) error {
	if simulated || e.cfg.DryRun {
		return nil
	}
	if e.isProtectedPID(pid) {
		return fmt.Errorf("protected pid %d", pid)
	}
	if !e.cfg.EnableSignals {
		return nil
	}
	return e.signaler.Signal(pid, syscall.SIGKILL)
}
