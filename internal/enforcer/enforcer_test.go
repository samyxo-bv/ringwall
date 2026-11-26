// SPDX-License-Identifier: Apache-2.0
package enforcer

import (
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

type mockSignaler struct {
	calls []struct {
		pid int
		sig syscall.Signal
	}
}

func (m *mockSignaler) Signal(pid int, sig syscall.Signal) error {
	m.calls = append(m.calls, struct {
		pid int
		sig syscall.Signal
	}{pid: pid, sig: sig})
	return nil
}

type mockFirewall struct {
	blocked []netip.Addr
}

func (m *mockFirewall) BlockIP(ip netip.Addr) error {
	m.blocked = append(m.blocked, ip)
	return nil
}

func TestEnforcerModesAndProtectedPIDs(t *testing.T) {
	ms := &mockSignaler{}
	mf := &mockFirewall{}
	enf := New(config.ModeInteractive, config.EnforcerConfig{EnableSignals: true, EnableNFTables: true}, ms, mf)

	// Protected PID 1 and self PID must NEVER be signaled.
	enf.Apply(model.Event{PID: 1}, model.ActionKill)
	enf.Apply(model.Event{PID: os.Getpid()}, model.ActionKill)
	if len(ms.calls) != 0 {
		t.Fatalf("expected 0 signals to protected PIDs, got %d", len(ms.calls))
	}

	// Interactive mode freezes on ActionKill instead of immediate SIGKILL.
	status, _ := enf.Apply(model.Event{PID: 4242}, model.ActionKill)
	if status != model.StatusFrozen || len(ms.calls) != 1 || ms.calls[0].sig != syscall.SIGSTOP {
		t.Fatalf("expected interactive SIGSTOP, got status=%s calls=%+v", status, ms.calls)
	}

	// BlockEgress freezes PID and blocks public IP.
	status, _ = enf.Apply(model.Event{PID: 4243, DstIP: "203.0.113.5"}, model.ActionBlockEgress)
	if status != model.StatusBlocked || len(mf.blocked) != 1 || mf.blocked[0].String() != "203.0.113.5" {
		t.Fatalf("expected blocked egress, got status=%s blocked=%+v", status, mf.blocked)
	}

	// Strict mode executes SIGKILL directly.
	msStrict := &mockSignaler{}
	enfStrict := New(config.ModeStrict, config.EnforcerConfig{EnableSignals: true}, msStrict, mf)
	status, _ = enfStrict.Apply(model.Event{PID: 5000}, model.ActionKill)
	if status != model.StatusKilled || len(msStrict.calls) != 1 || msStrict.calls[0].sig != syscall.SIGKILL {
		t.Fatalf("expected strict SIGKILL, got status=%s calls=%+v", status, msStrict.calls)
	}
}
