// SPDX-License-Identifier: Apache-2.0
package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/samyxo-bv/ringwall/internal/api"
	"github.com/samyxo-bv/ringwall/internal/audit"
	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/daemon"
	"github.com/samyxo-bv/ringwall/internal/enforcer"
	"github.com/samyxo-bv/ringwall/internal/guardian"
	"github.com/samyxo-bv/ringwall/internal/lineage"
	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/sensor"
)

func TestAPIAuthSimulateSetupAndAuditVerify(t *testing.T) {
	tmp := t.TempDir()
	cfg := config.Default()
	cfg.Sensor.Mode = "none"
	cfg.AuditLogPath = filepath.Join(tmp, "audit.jsonl")
	cfg.API.TokenFile = filepath.Join(tmp, "api.token")
	cfg.Patcher.VirtualPatchFile = filepath.Join(tmp, "99-virtual-patches.yaml")
	cfg.Patcher.ABUpdate.StatePath = filepath.Join(tmp, "ab-state.json")
	cfg.AI.Enabled = false

	pol, err := policy.NewEngine([]policy.Rule{
		{
			ID: "RW-AGENT-001", Name: "Agent SSH Key", Severity: model.SeverityCritical, Action: model.ActionFreeze,
			Match: policy.MatchSpec{EventTypes: []model.EventType{model.EventOpen}, PathGlobs: []string{"**/.ssh/id_*"}, AncestorAny: []string{"claude"}},
		},
		{
			ID: "RW-CORE-001", Name: "Reverse Shell", Severity: model.SeverityCritical, Action: model.ActionKill,
			Match: policy.MatchSpec{EventTypes: []model.EventType{model.EventExec}, CmdlineRegex: []string{`/dev/tcp/`}},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	alog, err := audit.Open(cfg.AuditLogPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sens, _ := sensor.New(cfg.Sensor)
	d := daemon.New("test", cfg, sens, lineage.NewTracker(nil), pol, enforcer.New(cfg.Mode, cfg.Enforcer, nil, nil), guardian.New(cfg.AI, nil), alog)
	d.SetStoragePaths(filepath.Join(tmp, "ringwall.yaml"), filepath.Join(tmp, "keys"))

	srv, err := api.NewServer(d, cfg.API)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Unauthenticated request MUST fail with 401.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", rec.Code)
	}

	// Setup info endpoint returns provider catalog + explainer.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/setup/info", nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("Venice.ai")) {
		t.Fatalf("expected 200 setup info with provider catalog, got %d: %s", rec.Code, rec.Body.String())
	}

	// Setup test-model against a local mock uncensored server MUST pass all 4 checks.
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{
					"content": `{"risk_score":95,"recommended_action":"kill","summary":"Reverse shell","reasoning":"tcp /dev/tcp"}`,
				}},
			},
		})
	}))
	defer mockLLM.Close()

	testPayload, _ := json.Marshal(map[string]any{
		"provider": "openai",
		"endpoint": mockLLM.URL,
		"model":    "abliterated-test",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/setup/test-model", bytes.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"passed":true`)) {
		t.Fatalf("expected 4-point onboarding test to pass, got %d: %s", rec.Code, rec.Body.String())
	}

	// Setup apply hot-reloads the AI Guardian pool without restart.
	applyPayload, _ := json.Marshal(map[string]any{
		"mode":     "interactive",
		"strategy": "tiered",
		"models": []map[string]any{{
			"name":        "local-test",
			"provider":    "openai",
			"endpoint":    mockLLM.URL,
			"model":       "abliterated-test",
			"tier":        1,
			"abliterated": true,
		}},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/setup/apply", bytes.NewReader(applyPayload))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"ai_enabled":true`)) {
		t.Fatalf("expected setup apply hot-reload to enable AI, got %d: %s", rec.Code, rec.Body.String())
	}

	// Authenticated simulation MUST succeed and record incidents.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/simulate", nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 simulate, got %d: %s", rec.Code, rec.Body.String())
	}
	var simResp struct {
		SimulatedCount int              `json:"simulated_count"`
		Incidents      []model.Incident `json:"incidents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &simResp); err != nil {
		t.Fatalf("unmarshal simulate: %v", err)
	}
	if simResp.SimulatedCount < 3 {
		t.Fatalf("expected >=3 simulated incidents, got %d", simResp.SimulatedCount)
	}

	// Operator kill action on first frozen incident.
	body, _ := json.Marshal(map[string]string{"action": "kill"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+simResp.Incidents[0].ID+"/action", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 operator action, got %d: %s", rec.Code, rec.Body.String())
	}

	// Audit chain verification MUST be valid.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 audit verify, got %d: %s", rec.Code, rec.Body.String())
	}

	// Self-healing endpoints: anti-lockout MUST reject virtual patch on /usr/bin/bash (400),
	// allow valid virtual patch on /usr/sbin/vuln-demo (200), list it, and revoke it (200).
	badVP := []byte(`{"id":"VP-BAD","cve":"CVE-2026-1","package":"bash","target_exe_paths":["/usr/bin/bash"],"action":"freeze"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/virtual-patches", bytes.NewReader(badVP))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 anti-lockout rejection for bash virtual patch, got %d: %s", rec.Code, rec.Body.String())
	}

	goodVP := []byte(`{"id":"VP-DEMO-1","cve":"CVE-2026-99","package":"vuln-demo","target_exe_paths":["/usr/sbin/vuln-demo"],"action":"freeze","rationale":"0-day containment"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/virtual-patches", bytes.NewReader(goodVP))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 applying valid virtual patch, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/virtual-patches/VP-DEMO-1", nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 revoking virtual patch, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/ab/status", nil)
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"active_slot":"A"`)) {
		t.Fatalf("expected 200 ab status, got %d: %s", rec.Code, rec.Body.String())
	}
}
