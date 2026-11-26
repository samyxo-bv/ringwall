// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"testing"

	"github.com/samyxo-bv/ringwall/internal/model"
)

func TestPolicyMatchesAIAgentSSHKeyAccess(t *testing.T) {
	eng, err := NewEngine([]Rule{
		{
			ID:       "RW-AGENT-001",
			Name:     "AI agent reading SSH private key",
			Severity: model.SeverityCritical,
			Action:   model.ActionFreeze,
			Match: MatchSpec{
				EventTypes:  []model.EventType{model.EventOpen},
				PathGlobs:   []string{"**/.ssh/id_*"},
				AncestorAny: []string{"claude", "codex", "cursor"},
				ExcludeComm: []string{"ssh", "ssh-agent"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Attack: Claude coding agent spawns cat reading SSH private key.
	ev := model.Event{
		Type: model.EventOpen,
		PID:  200,
		Comm: "cat",
		Path: "/home/alice/.ssh/id_ed25519",
		Ancestry: []model.ProcessInfo{
			{PID: 100, Comm: "claude", Cmdline: "claude"},
		},
	}
	matches, action, sev := eng.Evaluate(ev)
	if len(matches) != 1 || action != model.ActionFreeze || sev != model.SeverityCritical {
		t.Fatalf("expected critical freeze match, got matches=%d action=%s sev=%s", len(matches), action, sev)
	}

	// Legitimate ssh client without agent ancestry should NOT trigger.
	legit := model.Event{
		Type: model.EventOpen,
		PID:  201,
		Comm: "ssh",
		Path: "/home/alice/.ssh/id_ed25519",
		Ancestry: []model.ProcessInfo{
			{PID: 50, Comm: "bash"},
		},
	}
	matches, action, _ = eng.Evaluate(legit)
	if len(matches) != 0 || action != model.ActionAllow {
		t.Fatalf("expected legit ssh to be allowed, got matches=%d action=%s", len(matches), action)
	}

	// Scoped runtime allowlist only suppresses the exact (rule, comm, path).
	eng.AddRuntimeAllow("RW-AGENT-001", "cat", "/home/alice/.ssh/id_ed25519")
	matches, _, _ = eng.Evaluate(ev)
	if len(matches) != 0 {
		t.Fatalf("expected runtime allow to suppress exact event")
	}
	otherKey := ev
	otherKey.Path = "/home/alice/.ssh/id_rsa"
	matches, _, _ = eng.Evaluate(otherKey)
	if len(matches) != 1 {
		t.Fatalf("runtime allow must stay scoped to exact path")
	}
}

func TestMatchGlobDoubleStar(t *testing.T) {
	cases := []struct {
		pat, val string
		want     bool
	}{
		{"**/.ssh/id_*", "/home/user/.ssh/id_rsa", true},
		{"**/.ssh/id_*", "/root/.ssh/id_ed25519", true},
		{"**/.ssh/id_*", "/home/user/.ssh/config", false},
		{"/etc/cron*", "/etc/crontab", true},
		{"/etc/cron.d/*", "/etc/cron.d/evil", true},
		{"**/.aws/credentials", "/home/dev/.aws/credentials", true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pat, tc.val); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pat, tc.val, got, tc.want)
		}
	}
}
