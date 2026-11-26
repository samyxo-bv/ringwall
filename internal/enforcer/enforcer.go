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

var agentAncestorNames = map[string]bool{
	"claude": true, "codex": true, "cursor": true, "openclaw": true,
	"aider": true, "copilot": true, "mcp": true, "agent": true,
}

// Signaler abstracts pidfd/starttime-verified OS signaling for unit testing.
type Signaler interface {
	SignalVerified(pid int, expectedStartTime uint64, sig syscall.Signal) error
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
	if ip.Zone() != "" {
		return fmt.Errorf("refusing IP with zone identifier %q", ip.String())
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("refusing to block non-public address %s", ip)
	}
	parts := strings.Fields(f.table)
	family, table := parts[0], parts[1]
	setName := "blocked_v4"
	if ip.Is6() {
		setName = "blocked_v6"
	}
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

// Apply enforces a deterministic or escalated action and returns (status, cgroupFreezePath, note).
func (e *Enforcer) Apply(ev model.Event, action model.Action) (model.IncidentStatus, string, string) {
	if action == model.ActionAllow || action == model.ActionWarn {
		return model.StatusOpen, "", "logged only"
	}
	if ev.Simulated {
		switch action {
		case model.ActionKill:
			if e.mode == config.ModeStrict {
				return model.StatusKilled, "", "simulated strict enforcement: process would receive SIGKILL"
			}
			return model.StatusFrozen, "", "simulated interactive enforcement: process frozen via pidfd SIGSTOP awaiting approval"
		case model.ActionBlockEgress:
			return model.StatusBlocked, "", fmt.Sprintf("simulated egress block for %s and SIGSTOP", ev.DstIP)
		default:
			return model.StatusFrozen, "", "simulated enforcement: process frozen via pidfd SIGSTOP"
		}
	}
	if e.mode == config.ModeAudit || e.cfg.DryRun {
		return model.StatusOpen, "", fmt.Sprintf("audit/dry-run mode: would execute %s on pid %d", action, ev.PID)
	}
	if e.isProtectedPID(ev.PID) {
		return model.StatusOpen, "", fmt.Sprintf("protected pid %d: signal skipped", ev.PID)
	}

	freezeTree := func() (model.IncidentStatus, string, string) {
		var notes []string
		cgPath := ""
		if p, ok := TryFreezeCgroup(ev.PID); ok {
			cgPath = p
			notes = append(notes, fmt.Sprintf("cgroup frozen (%s)", p))
		}
		if e.cfg.EnableSignals {
			if err := e.signaler.SignalVerified(ev.PID, ev.StartTime, syscall.SIGSTOP); err != nil {
				if cgPath == "" {
					return model.StatusOpen, "", fmt.Sprintf("SIGSTOP failed for pid %d: %v", ev.PID, err)
				}
				notes = append(notes, fmt.Sprintf("pid %d SIGSTOP note: %v", ev.PID, err))
			} else {
				notes = append(notes, fmt.Sprintf("pid %d frozen via pidfd SIGSTOP", ev.PID))
			}
			// Also freeze any AI-agent ancestor so it cannot send SIGCONT to its frozen child.
			for _, anc := range ev.Ancestry {
				if agentAncestorNames[strings.ToLower(anc.Comm)] && !e.isProtectedPID(anc.PID) {
					if err := e.signaler.SignalVerified(anc.PID, anc.StartTime, syscall.SIGSTOP); err == nil {
						notes = append(notes, fmt.Sprintf("agent ancestor %s(pid=%d) frozen", anc.Comm, anc.PID))
					}
				}
			}
		}
		if len(notes) == 0 {
			return model.StatusOpen, "", "signals disabled in config"
		}
		return model.StatusFrozen, cgPath, strings.Join(notes, "; ")
	}

	switch action {
	case model.ActionFreeze:
		return freezeTree()

	case model.ActionBlockEgress:
		st, cgPath, freezeNote := freezeTree()
		notes := []string{freezeNote}
		if e.cfg.EnableNFTables && ev.DstIP != "" {
			if ip, err := netip.ParseAddr(ev.DstIP); err == nil {
				if err := e.firewall.BlockIP(ip); err == nil {
					st = model.StatusBlocked
					notes = append(notes, fmt.Sprintf("blocked egress %s in nftables", ip))
				} else {
					notes = append(notes, fmt.Sprintf("nftables block failed: %v", err))
				}
			}
		}
		return st, cgPath, strings.Join(notes, "; ")

	case model.ActionKill:
		if e.mode == config.ModeInteractive {
			st, cgPath, note := freezeTree()
			return st, cgPath, "interactive mode (pending kill/resume): " + note
		}
		if !e.cfg.EnableSignals {
			return model.StatusOpen, "", "signals disabled in config"
		}
		if err := e.signaler.SignalVerified(ev.PID, ev.StartTime, syscall.SIGKILL); err != nil {
			return model.StatusOpen, "", fmt.Sprintf("SIGKILL failed for pid %d: %v", ev.PID, err)
		}
		return model.StatusKilled, "", fmt.Sprintf("strict mode: pid %d terminated via pidfd SIGKILL", ev.PID)
	}

	return model.StatusOpen, "", "no enforcement action"
}

func (e *Enforcer) Resume(ev model.Event, cgroupPath string) error {
	if ev.Simulated || e.cfg.DryRun {
		return nil
	}
	if e.isProtectedPID(ev.PID) {
		return fmt.Errorf("protected pid %d", ev.PID)
	}
	if cgroupPath != "" {
		if err := ThawCgroup(cgroupPath); err != nil {
			return err
		}
	}
	if !e.cfg.EnableSignals {
		return nil
	}
	for _, anc := range ev.Ancestry {
		if agentAncestorNames[strings.ToLower(anc.Comm)] && !e.isProtectedPID(anc.PID) {
			_ = e.signaler.SignalVerified(anc.PID, anc.StartTime, syscall.SIGCONT)
		}
	}
	return e.signaler.SignalVerified(ev.PID, ev.StartTime, syscall.SIGCONT)
}

func (e *Enforcer) Kill(ev model.Event, cgroupPath string) error {
	if ev.Simulated || e.cfg.DryRun {
		return nil
	}
	if e.isProtectedPID(ev.PID) {
		return fmt.Errorf("protected pid %d", ev.PID)
	}
	if !e.cfg.EnableSignals {
		return nil
	}
	err := e.signaler.SignalVerified(ev.PID, ev.StartTime, syscall.SIGKILL)
	if cgroupPath != "" {
		_ = ThawCgroup(cgroupPath)
	}
	return err
}
