// SPDX-License-Identifier: Apache-2.0
package guardian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

const virtualPatchSystemPrompt = `You are Ringwall's defensive Linux virtual-patching assistant.
Given an unpatched CVE / zero-day advisory affecting a local Linux package, propose a minimal, temporary, declarative Ringwall containment rule until an upstream package patch is released.
NEVER propose shell commands, C code, or blocking core OS binaries (systemd, init, bash, sh, login, sshd, ringwalld, apt-get, dpkg).
Respond ONLY with strict JSON matching:
{"target_exe_paths":["/usr/sbin/..."],"target_path_globs":[],"target_ports":[],"action":"freeze|block_egress","ttl_hours":72,"rationale":"short technical reason"}`

// VirtualPatchProposal is a structured, untrusted AI recommendation that MUST pass deterministic
// anti-lockout validation in internal/patcher before activation.
type VirtualPatchProposal struct {
	TargetExePaths  []string     `json:"target_exe_paths"`
	TargetPathGlobs []string     `json:"target_path_globs"`
	TargetPorts     []uint16     `json:"target_ports"`
	Action          model.Action `json:"action"`
	TTLHours        int          `json:"ttl_hours"`
	Rationale       string       `json:"rationale"`
	ModelUsed       string       `json:"model_used,omitempty"`
}

// ProposeVirtualPatch queries the configured uncensored/abliterated model pool for a defensive
// declarative containment proposal for an unpatched 0-day/CVE.
func (g *Guardian) ProposeVirtualPatch(ctx context.Context, cve, pkg, summary string, runningBins []string) (*VirtualPatchProposal, error) {
	g.mu.RLock()
	cfg := g.cfg
	g.mu.RUnlock()

	models := cfg.EffectiveModels()
	if len(models) == 0 {
		return nil, fmt.Errorf("no AI models configured")
	}

	payloadObj := map[string]any{
		"cve":          sanitizeField(cve, 40),
		"package":      sanitizeField(pkg, 80),
		"summary":      sanitizeField(RedactSecrets(summary), 300),
		"running_bins": runningBins,
	}
	b, _ := json.Marshal(payloadObj)
	userPrompt := "<untrusted_advisory>\n" + string(b) + "\n</untrusted_advisory>"

	var lastErr error
	for _, m := range models {
		raw, err := g.callRawWithSystemPrompt(ctx, m, virtualPatchSystemPrompt, userPrompt)
		if err != nil {
			lastErr = err
			continue
		}
		if DetectRefusal(raw) {
			lastErr = fmt.Errorf("model %s refused virtual patch prompt", m.Name)
			continue
		}
		prop, perr := parseVirtualPatchJSON(raw)
		if perr != nil {
			lastErr = perr
			continue
		}
		prop.ModelUsed = m.Model
		return prop, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all AI models failed to propose virtual patch")
	}
	return nil, lastErr
}

func (g *Guardian) callRawWithSystemPrompt(ctx context.Context, m config.AIModelConfig, sysPrompt, userPrompt string) (string, error) {
	timeout := time.Duration(m.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	apiKey, err := config.ResolveAPIKey(m)
	if err != nil {
		return "", err
	}

	if m.Provider == "ollama" {
		body := map[string]any{
			"model":   m.Model,
			"stream":  false,
			"format":  "json",
			"options": map[string]any{"temperature": 0.0},
			"messages": []map[string]string{
				{"role": "system", "content": sysPrompt},
				{"role": "user", "content": userPrompt},
			},
		}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(m.Endpoint, "/")+"/api/chat", bytes.NewReader(data))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := g.client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("ollama HTTP %d", resp.StatusCode)
		}
		var out struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
			return "", err
		}
		return out.Message.Content, nil
	}

	body := map[string]any{
		"model":       m.Model,
		"temperature": 0.0,
		"max_tokens":  350,
		"messages": []map[string]string{
			{"role": "system", "content": sysPrompt},
			{"role": "user", "content": userPrompt},
		},
	}
	if m.Provider == "venice" {
		body["venice_parameters"] = map[string]any{
			"include_venice_system_prompt": false,
			"web_enabled":                  false,
		}
	}
	data, _ := json.Marshal(body)
	base := strings.TrimRight(m.Endpoint, "/")
	endpoint := base + "/v1/chat/completions"
	if strings.HasSuffix(base, "/v1") || strings.HasSuffix(base, "/api/v1") {
		endpoint = base + "/chat/completions"
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s HTTP %d", m.Provider, resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("empty choices")
	}
	return out.Choices[0].Message.Content, nil
}

func parseVirtualPatchJSON(raw string) (*VirtualPatchProposal, error) {
	trimmed := strings.TrimSpace(raw)
	start := strings.IndexByte(trimmed, '{')
	end := strings.LastIndexByte(trimmed, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no json object in virtual patch response")
	}
	var parsed struct {
		TargetExePaths  []string `json:"target_exe_paths"`
		TargetPathGlobs []string `json:"target_path_globs"`
		TargetPorts     []uint16 `json:"target_ports"`
		Action          string   `json:"action"`
		TTLHours        int      `json:"ttl_hours"`
		Rationale       string   `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(trimmed[start:end+1]), &parsed); err != nil {
		return nil, err
	}
	act := normalizeAction(parsed.Action)
	if act == model.ActionAllow || act == model.ActionWarn {
		act = model.ActionFreeze
	}
	ttl := parsed.TTLHours
	if ttl <= 0 || ttl > 168 {
		ttl = 72
	}
	return &VirtualPatchProposal{
		TargetExePaths:  parsed.TargetExePaths,
		TargetPathGlobs: parsed.TargetPathGlobs,
		TargetPorts:     parsed.TargetPorts,
		Action:          act,
		TTLHours:        ttl,
		Rationale:       strings.TrimSpace(parsed.Rationale),
	}, nil
}
