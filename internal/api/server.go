// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/daemon"
	"github.com/samyxo-bv/ringwall/internal/patcher"
	"github.com/samyxo-bv/ringwall/internal/setup"
)

//go:embed ui/index.html
var uiFS embed.FS

type Server struct {
	daemon *daemon.Daemon
	cfg    config.APIConfig
	token  string
	http   *http.Server
}

func NewServer(d *daemon.Daemon, cfg config.APIConfig) (*Server, error) {
	tok, err := loadOrGenerateToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		daemon: d,
		cfg:    cfg,
		token:  tok,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/v1/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/v1/incidents", s.requireAuth(s.handleIncidents))
	mux.HandleFunc("/api/v1/incidents/", s.requireAuth(s.handleIncidentAction))
	mux.HandleFunc("/api/v1/simulate", s.requireAuth(s.handleSimulate))
	mux.HandleFunc("/api/v1/audit/verify", s.requireAuth(s.handleAuditVerify))
	mux.HandleFunc("/api/v1/events", s.requireAuth(s.handleSSE))
	mux.HandleFunc("/api/v1/setup/info", s.requireAuth(s.handleSetupInfo))
	mux.HandleFunc("/api/v1/setup/test-model", s.requireAuth(s.handleSetupTestModel))
	mux.HandleFunc("/api/v1/setup/apply", s.requireAuth(s.handleSetupApply))
	mux.HandleFunc("/api/v1/scan", s.requireAuth(s.handleScan))
	mux.HandleFunc("/api/v1/patch", s.requireAuth(s.handlePatch))
	mux.HandleFunc("/api/v1/virtual-patches", s.requireAuth(s.handleVirtualPatches))
	mux.HandleFunc("/api/v1/virtual-patches/", s.requireAuth(s.handleVirtualPatchItem))
	mux.HandleFunc("/api/v1/ab/status", s.requireAuth(s.handleABStatus))
	mux.HandleFunc("/api/v1/ab/stage", s.requireAuth(s.handleABStage))

	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

func (s *Server) Token() string { return s.token }

func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shCtx)
	}()
	err := s.http.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func loadOrGenerateToken(path string) (string, error) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			t := strings.TrimSpace(string(b))
			if len(t) >= 32 {
				return t, nil
			}
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	tok := hex.EncodeToString(raw[:])
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", fmt.Errorf("create token dir: %w", err)
		}
		if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("write token file %s: %w", path, err)
		}
		_ = os.Chmod(path, 0o600)
	}
	return tok, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		got := ""
		if strings.HasPrefix(auth, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		} else if q := r.URL.Query().Get("token"); q != "" && r.URL.Path == "/api/v1/events" {
			got = q
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.daemon.Status())
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.daemon.Incidents())
}

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "action" || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	inc, err := s.daemon.HandleOperatorAction(id, req.Action)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	incidents := s.daemon.SimulateAttack(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"simulated_count": len(incidents),
		"incidents":       incidents,
	})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, err := s.daemon.VerifyAuditLog()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"valid": false, "entries": n, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "entries": n})
}

func (s *Server) handleSetupInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	env := setup.DetectEnvironment(r.Context())
	cfg := s.daemon.Config()
	// Strip any sensitive file paths when exposing current summary to UI.
	models := cfg.AI.EffectiveModels()
	redacted := make([]map[string]any, 0, len(models))
	for _, m := range models {
		redacted = append(redacted, map[string]any{
			"name":        m.Name,
			"provider":    m.Provider,
			"endpoint":    m.Endpoint,
			"model":       m.Model,
			"tier":        m.Tier,
			"abliterated": m.Abliterated,
			"has_api_key": m.APIKeyEnv != "" || m.APIKeyFile != "",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"explainer":   setup.Explainer(),
		"providers":   setup.ProviderCatalog(),
		"environment": env,
		"current": map[string]any{
			"mode":               cfg.Mode,
			"strategy":           cfg.AI.Strategy,
			"escalate_threshold": cfg.AI.EscalateThreshold,
			"models":             redacted,
		},
	})
}

func (s *Server) handleSetupTestModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider            string `json:"provider"`
		Endpoint            string `json:"endpoint"`
		Model               string `json:"model"`
		APIKey              string `json:"api_key"`
		AllowRemoteEndpoint bool   `json:"allow_remote_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	allowRemote := req.AllowRemoteEndpoint || req.Provider == "venice" || req.Provider == "openrouter"
	mc := config.AIModelConfig{
		Name:                "setup-probe",
		Provider:            req.Provider,
		Endpoint:            req.Endpoint,
		Model:               req.Model,
		AllowRemoteEndpoint: allowRemote,
		TimeoutSec:          20,
	}
	result := s.daemon.TestAIModel(r.Context(), mc, req.APIKey)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSetupApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req setup.ApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32768)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	cfgPath, keyDir := s.daemon.StoragePaths()
	next, err := setup.BuildAndSaveConfig(s.daemon.Config(), cfgPath, keyDir, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.daemon.ReloadConfig(next)
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":  true,
		"status": s.daemon.Status(),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if rep := s.daemon.LastScan(); rep != nil {
			writeJSON(w, http.StatusOK, rep)
			return
		}
		writeJSON(w, http.StatusOK, s.daemon.RunScan(r.Context()))
	case http.MethodPost:
		writeJSON(w, http.StatusOK, s.daemon.RunScan(r.Context()))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DryRun *bool `json:"dry_run,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
	}
	writeJSON(w, http.StatusOK, s.daemon.RunPatchCycle(r.Context(), req.DryRun))
}

func (s *Server) handleVirtualPatches(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.daemon.VirtualPatches())
	case http.MethodPost:
		var vp patcher.VirtualPatch
		if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&vp); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		applied, err := s.daemon.ApplyVirtualPatch(vp)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, applied)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVirtualPatchItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/virtual-patches/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if !s.daemon.RevokeVirtualPatch(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "virtual patch not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
}

func (s *Server) handleABStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.daemon.ABStatus())
}

func (s *Server) handleABStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var m patcher.ABManifest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32768)).Decode(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	st, err := s.daemon.StageABUpdate(r.Context(), m)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.daemon.Subscribe()
	defer unsub()

	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"ok\":true}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case inc, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(inc)
			_, _ = fmt.Fprintf(w, "event: incident\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
