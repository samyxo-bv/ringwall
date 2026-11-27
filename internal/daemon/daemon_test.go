// SPDX-License-Identifier: Apache-2.0
package daemon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/samyxo-bv/ringwall/internal/audit"
	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/daemon"
	"github.com/samyxo-bv/ringwall/internal/enforcer"
	"github.com/samyxo-bv/ringwall/internal/guardian"
	"github.com/samyxo-bv/ringwall/internal/lineage"
	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
)

type fakeSensor struct {
	drops atomic.Uint64
}

func (f *fakeSensor) Mode() string                                       { return "fake" }
func (f *fakeSensor) Dropped() uint64                                    { return f.drops.Load() }
func (f *fakeSensor) Start(ctx context.Context, _ chan<- model.Event) error { <-ctx.Done(); return nil }

type recordingSignaler struct {
	mu    sync.Mutex
	calls []syscall.Signal
}

func (r *recordingSignaler) SignalVerified(_ int, _ uint64, sig syscall.Signal) error {
	r.mu.Lock()
	r.calls = append(r.calls, sig)
	r.mu.Unlock()
	return nil
}

func TestOperatorDecisionCannotBeOverwrittenBySlowAI(t *testing.T) {
	// Slow AI server that tries to escalate to kill AFTER operator already resumed.
	releaseAI := make(chan struct{})
	slowAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-releaseAI
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{
					"content": `{"risk_score":95,"recommended_action":"kill","summary":"Late AI escalation","reasoning":"delayed"}`,
				}},
			},
		})
	}))
	defer slowAI.Close()

	cfg := config.Default()
	cfg.Mode = config.ModeInteractive
	cfg.AuditLogPath = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.AI = config.AIConfig{
		Enabled:  true,
		Strategy: "failover",
		Models: []config.AIModelConfig{{
			Name:     "slow-ai",
			Provider: "openai",
			Endpoint: slowAI.URL,
			Model:    "slow",
			Tier:     1,
		}},
	}

	pol, _ := policy.NewEngine([]policy.Rule{{
		ID: "RW-FREEZE-1", Name: "Suspicious open", Severity: model.SeverityHigh, Action: model.ActionFreeze,
		Match: policy.MatchSpec{EventTypes: []model.EventType{model.EventOpen}, PathGlobs: []string{"/tmp/watch"}},
	}})
	alog, _ := audit.Open(cfg.AuditLogPath)
	sig := &recordingSignaler{}
	enf := enforcer.New(cfg.Mode, cfg.Enforcer, sig, nil)
	d := daemon.New("test", cfg, &fakeSensor{}, lineage.NewTracker(nil), pol, enf, guardian.New(cfg.AI, nil), alog)

	inc := d.ProcessEvent(context.Background(), model.Event{
		Type: model.EventOpen, PID: 8888, StartTime: 1001, Comm: "python3", Exe: "/usr/bin/python3", Path: "/tmp/watch",
	}, false)
	if inc == nil || inc.Status != model.StatusFrozen {
		t.Fatalf("expected frozen incident, got %+v", inc)
	}

	// Operator resumes/approves BEFORE slow AI responds.
	updated, err := d.HandleOperatorAction(inc.ID, "approve")
	if err != nil || updated.Status != model.StatusAllowed {
		t.Fatalf("expected approve -> allowed, got status=%v err=%v", updated, err)
	}

	// Second operator action on already-finalized incident MUST be rejected (prevents stale PID reuse kill).
	if _, err := d.HandleOperatorAction(inc.ID, "kill"); err == nil {
		t.Fatalf("expected kill on already-finalized incident to be rejected")
	}

	// Now let slow AI finish; it MUST NOT overwrite StatusAllowed or send SIGKILL!
	close(releaseAI)
	time.Sleep(150 * time.Millisecond)

	after := d.GetIncident(inc.ID)
	if after.Status != model.StatusAllowed {
		t.Fatalf("slow AI overwrote operator decision! got status=%s", after.Status)
	}
	sig.mu.Lock()
	defer sig.mu.Unlock()
	for _, s := range sig.calls {
		if s == syscall.SIGKILL {
			t.Fatalf("slow AI illegally sent %v after operator decision", s)
		}
	}
}

func TestSelfPIDSkippedDropAlertAndGitCommitNoFalseFreeze(t *testing.T) {
	fs := &fakeSensor{}
	cfg := config.Default()
	cfg.AuditLogPath = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.AI.Enabled = false

	pol, _ := policy.NewEngine([]policy.Rule{{
		ID: "RW-RM", Name: "Destructive rm", Severity: model.SeverityCritical, Action: model.ActionKill,
		Match: policy.MatchSpec{EventTypes: []model.EventType{model.EventExec}, DestructiveRM: true},
	}})
	alog, _ := audit.Open(cfg.AuditLogPath)
	sig := &recordingSignaler{}
	d := daemon.New("test", cfg, fs, lineage.NewTracker(nil), pol, enforcer.New(cfg.Mode, cfg.Enforcer, sig, nil), guardian.New(cfg.AI, nil), alog)

	// Self PID is always ignored.
	if inc := d.ProcessEvent(context.Background(), model.Event{Type: model.EventExec, PID: os.Getpid(), Argv: []string{"rm", "-rf", "/"}}, true); inc != nil {
		t.Fatalf("self PID must never trigger an incident")
	}

	// Normal git commit mentioning "system prompt" MUST warn only, NEVER freeze!
	gitInc := d.ProcessEvent(context.Background(), model.Event{
		Type: model.EventExec, PID: 7777, Comm: "git", Exe: "/usr/bin/git",
		Cmdline: `git commit -m "update system prompt"`,
		Argv:    []string{"git", "commit", "-m", "update system prompt"},
	}, true)
	if gitInc == nil || gitInc.DeterministicAction != model.ActionWarn || gitInc.Status == model.StatusFrozen {
		t.Fatalf("git commit mentioning system prompt should only warn, got %+v", gitInc)
	}

	// Simulated sensor drops MUST create RW-SYS-DROP incident and reflect in Status().
	fs.drops.Add(42)
	d.CheckDrops()
	if st := d.Status(); st.DroppedEvents != 42 {
		t.Fatalf("expected DroppedEvents=42, got %d", st.DroppedEvents)
	}
	foundDrop := false
	for _, inc := range d.Incidents() {
		if len(inc.Matches) > 0 && inc.Matches[0].RuleID == "RW-SYS-DROP" {
			foundDrop = true
		}
	}
	if !foundDrop {
		t.Fatalf("expected RW-SYS-DROP incident when sensor drops events")
	}
}
