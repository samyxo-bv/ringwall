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
		pid       int
		startTime uint64
		sig       syscall.Signal
	}
}

func (m *mockSignaler) SignalVerified(pid int, startTime uint64, sig syscall.Signal) error {
	m.calls = append(m.calls, struct {
		pid       int
		startTime uint64
		sig       syscall.Signal
	}{pid: pid, startTime: startTime, sig: sig})
	return nil
}

type mockFirewall struct {
	blocked []netip.Addr
}

func (m *mockFirewall) BlockIP(ip netip.Addr) error {
	m.blocked = append(m.blocked, ip)
	return nil
}

func TestEnforcerModesAgentAncestorFreezeAndNFTValidation(t *testing.T) {
	ms := &mockSignaler{}
	mf := &mockFirewall{}
	enf := New(config.ModeInteractive, config.EnforcerConfig{EnableSignals: true, EnableNFTables: true}, ms, mf)

	// Protected PID 1 and self PID must NEVER be signaled.
	enf.Apply(model.Event{PID: 1}, model.ActionKill)
	enf.Apply(model.Event{PID: os.Getpid()}, model.ActionKill)
	if len(ms.calls) != 0 {
		t.Fatalf("expected 0 signals to protected PIDs, got %d", len(ms.calls))
	}

	// Interactive mode freezes both offending child AND AI-agent ancestor with starttime bound.
	ev := model.Event{
		PID:       4242,
		StartTime: 99901,
		Ancestry:  []model.ProcessInfo{{PID: 4200, StartTime: 99800, Comm: "claude"}},
	}
	status, _, _ := enf.Apply(ev, model.ActionKill)
	if status != model.StatusFrozen || len(ms.calls) != 2 {
		t.Fatalf("expected child + agent ancestor frozen, got status=%s calls=%+v", status, ms.calls)
	}
	if ms.calls[0].pid != 4242 || ms.calls[0].startTime != 99901 || ms.calls[1].pid != 4200 || ms.calls[1].startTime != 99800 {
		t.Fatalf("expected starttime-verified signals, got %+v", ms.calls)
	}

	// BlockEgress freezes PID and blocks public IP.
	status, _, _ = enf.Apply(model.Event{PID: 4243, DstIP: "203.0.113.5"}, model.ActionBlockEgress)
	if status != model.StatusBlocked || len(mf.blocked) != 1 || mf.blocked[0].String() != "203.0.113.5" {
		t.Fatalf("expected blocked egress, got status=%s blocked=%+v", status, mf.blocked)
	}

	// nftFirewall rejects zoned IPv6 and private/loopback addresses.
	fw := nftFirewall{table: "inet ringwall"}
	if err := fw.BlockIP(netip.MustParseAddr("fe80::1%eth0")); err == nil {
		t.Fatalf("expected zoned IPv6 to be rejected")
	}
	if err := fw.BlockIP(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatalf("expected loopback IP to be rejected")
	}

	// Strict mode executes SIGKILL directly.
	msStrict := &mockSignaler{}
	enfStrict := New(config.ModeStrict, config.EnforcerConfig{EnableSignals: true}, msStrict, mf)
	status, _, _ = enfStrict.Apply(model.Event{PID: 5000, StartTime: 555}, model.ActionKill)
	if status != model.StatusKilled || len(msStrict.calls) != 1 || msStrict.calls[0].sig != syscall.SIGKILL {
		t.Fatalf("expected strict SIGKILL, got status=%s calls=%+v", status, msStrict.calls)
	}
}
