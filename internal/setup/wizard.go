// SPDX-License-Identifier: Apache-2.0
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/samyxo-bv/ringwall/internal/config"
)

var safeSlugRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,48}$`)

// ProviderInfo describes an AI Guardian provider in plain language for non-technical users.
type ProviderInfo struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"display_name"`
	Kind              string   `json:"kind"` // local | cloud
	Privacy           string   `json:"privacy"`
	Cost              string   `json:"cost"`
	NeedsGPU          string   `json:"needs_gpu"`
	NeedsAPIKey       bool     `json:"needs_api_key"`
	DefaultEndpoint   string   `json:"default_endpoint"`
	RecommendedModels []string `json:"recommended_models"`
	DocsURL           string   `json:"docs_url"`
	Summary           string   `json:"summary"`
	QuickSteps        []string `json:"quick_steps"`
}

// EnvironmentInfo summarizes what Ringwall automatically detected on this computer.
type EnvironmentInfo struct {
	TotalRAMGB       int      `json:"total_ram_gb"`
	HasNVIDIA        bool     `json:"has_nvidia"`
	OllamaRunning    bool     `json:"ollama_running"`
	OllamaModels     []string `json:"ollama_models,omitempty"`
	LlamaCppRunning  bool     `json:"llamacpp_running"`
	RecommendedRoute string   `json:"recommended_route"`
	RecommendedHint  string   `json:"recommended_hint"`
}

// Explainer returns plain-language onboarding guidance explaining why uncensored/abliterated models matter.
func Explainer() map[string]string {
	return map[string]string{
		"headline": "Why Ringwall uses an Uncensored (Abliterated) AI Model",
		"why": "Standard cloud AI models (like default ChatGPT/Claude) often refuse to inspect hacker commands, reverse shells, or malware logs because of safety filters. When a real attack happens, a censored model replies 'I cannot assist with that' and goes blind. An abliterated / uncensored model analyzes threat telemetry honestly without refusing.",
		"safety": "Your computer is ALWAYS protected first by Ringwall's hard kernel/policy wall (0 ms). The AI model cannot disable or weaken a block — it only explains what happened in plain English and helps catch tricky attacks.",
		"choice": "No heavy GPU? Pick a privacy-first uncensored cloud API (like Venice.ai or OpenRouter). Have 8 GB+ RAM or a GPU? Run a free 100% offline abliterated model via Ollama. Want maximum strength? Combine both in Tiered mode.",
	}
}

// ProviderCatalog lists ready-to-use local and cloud providers for the Setup Wizard.
func ProviderCatalog() []ProviderInfo {
	return []ProviderInfo{
		{
			ID:              "ollama",
			DisplayName:     "Local Ollama (Free & 100% Offline)",
			Kind:            "local",
			Privacy:         "Maximum — nothing ever leaves your machine",
			Cost:            "Free",
			NeedsGPU:        "Optional (8 GB+ RAM for 3B, 16 GB+ or GPU for 7B/8B)",
			NeedsAPIKey:     false,
			DefaultEndpoint: "http://127.0.0.1:11434",
			RecommendedModels: []string{
				"huihui_ai/qwen2.5-coder-abliterated:7b",
				"huihui_ai/qwen2.5-coder-abliterated:3b",
				"dolphin-llama3:8b",
				"qwen2.5-coder:3b",
			},
			DocsURL: "https://ollama.com/download",
			Summary: "Best choice if your PC/server has 8–16 GB+ RAM or a GPU. Runs abliterated open-source models completely offline.",
			QuickSteps: []string{
				"Install Ollama from https://ollama.com/download (or 'curl -fsSL https://ollama.com/install.sh | sh').",
				"Download an abliterated coder/security model: ollama pull huihui_ai/qwen2.5-coder-abliterated:7b",
				"Click 'Test Connection & Security Check' below to confirm it does not refuse threat alerts.",
			},
		},
		{
			ID:              "venice",
			DisplayName:     "Venice.ai API (Uncensored Privacy Cloud — No GPU Needed)",
			Kind:            "cloud",
			Privacy:         "High — zero-data-retention private inference",
			Cost:            "Pay-as-you-go / Pro API key",
			NeedsGPU:        "No (runs on any tiny laptop or VM)",
			NeedsAPIKey:     true,
			DefaultEndpoint: "https://api.venice.ai/api/v1",
			RecommendedModels: []string{
				"venice-uncensored-1-2",
				"hermes-3-llama-3.1-405b",
			},
			DocsURL: "https://venice.ai/settings/api",
			Summary: "Easiest option if you don't have a strong GPU. Native uncensored models with private zero-retention API.",
			QuickSteps: []string{
				"Create an API key at https://venice.ai/settings/api.",
				"Select model 'venice-uncensored-1-2' and paste your API key below (saved safely in a 0600 key file, never in YAML).",
				"Click 'Test Connection & Security Check' to verify your key and confirm zero refusals.",
			},
		},
		{
			ID:              "openrouter",
			DisplayName:     "OpenRouter API (Multiple Uncensored Models, One Key)",
			Kind:            "cloud",
			Privacy:         "Depends on selected model provider (choose zero-retention routes)",
			Cost:            "Pay-per-token",
			NeedsGPU:        "No",
			NeedsAPIKey:     true,
			DefaultEndpoint: "https://openrouter.ai/api/v1",
			RecommendedModels: []string{
				"cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
				"nousresearch/hermes-3-llama-3.1-70b",
			},
			DocsURL: "https://openrouter.ai/keys",
			Summary: "Flexible gateway to switch between multiple uncensored/Dolphin/Hermes models with a single API key.",
			QuickSteps: []string{
				"Create an API key at https://openrouter.ai/keys.",
				"Pick a Dolphin or Hermes uncensored model ID and paste your key below.",
				"Run the 4-point Security Check to verify your key works without refusals.",
			},
		},
		{
			ID:              "openai",
			DisplayName:     "Local llama.cpp / Custom OpenAI-Compatible API",
			Kind:            "local",
			Privacy:         "Full control (localhost or your own vLLM / llama-server / cloud provider)",
			Cost:            "Free locally / depends on endpoint",
			NeedsGPU:        "Optional for local GGUF",
			NeedsAPIKey:     false,
			DefaultEndpoint: "http://127.0.0.1:8080",
			RecommendedModels: []string{
				"foundation-sec-8b",
				"qwen2.5-coder-7b-abliterated",
			},
			DocsURL: "https://github.com/ggml-org/llama.cpp",
			Summary: "Connect directly to local llama-server (GGUF), vLLM, LM Studio, or any custom uncensored OpenAI-compatible API.",
			QuickSteps: []string{
				"Start llama-server on 127.0.0.1:8080 (or enter your custom HTTPS API URL).",
				"Enter the model name and optional API key, then run the live Security Check.",
			},
		},
	}
}

// DetectEnvironment checks local RAM, NVIDIA GPU, Ollama, and llama-server availability.
func DetectEnvironment(ctx context.Context) EnvironmentInfo {
	info := EnvironmentInfo{
		TotalRAMGB: detectRAMGB(),
		HasNVIDIA:  detectNVIDIA(),
	}

	client := &http.Client{Timeout: 2 * time.Second}

	if models, ok := probeOllama(ctx, client, "http://127.0.0.1:11434"); ok {
		info.OllamaRunning = true
		info.OllamaModels = models
	}
	if probeLlamaCpp(ctx, client, "http://127.0.0.1:8080") {
		info.LlamaCppRunning = true
	}

	switch {
	case info.OllamaRunning && len(info.OllamaModels) > 0:
		info.RecommendedRoute = "ollama"
		info.RecommendedHint = fmt.Sprintf("Ollama is already running with %d local model(s). Test one now or pull an abliterated coder model.", len(info.OllamaModels))
	case info.HasNVIDIA || info.TotalRAMGB >= 16:
		info.RecommendedRoute = "ollama"
		info.RecommendedHint = fmt.Sprintf("Detected %d GB RAM (GPU=%v). Your hardware can run a fast 7B–8B abliterated model offline with Ollama!", info.TotalRAMGB, info.HasNVIDIA)
	case info.TotalRAMGB >= 8:
		info.RecommendedRoute = "ollama"
		info.RecommendedHint = "Detected ~8+ GB RAM. You can run a compact 3B local abliterated model in Ollama, or use Venice.ai/OpenRouter for zero local CPU load."
	default:
		info.RecommendedRoute = "venice"
		info.RecommendedHint = "Low RAM/VM detected. A privacy-first uncensored API (Venice.ai or OpenRouter) gives strong security analysis with zero local GPU/RAM overhead."
	}
	return info
}

func detectRAMGB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return int((kb + 1024*1024 - 1) / (1024 * 1024))
				}
			}
		}
	}
	return 0
}

func detectNVIDIA() bool {
	if _, err := os.Stat("/dev/nvidia0"); err == nil {
		return true
	}
	_, err := exec.LookPath("nvidia-smi")
	return err == nil
}

func probeOllama(ctx context.Context, client *http.Client, base string) ([]string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/tags", nil)
	if err != nil {
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, false
	}
	defer resp.Body.Close()
	var parsed struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, true
	}
	out := make([]string, 0, len(parsed.Models))
	for _, m := range parsed.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	return out, true
}

func probeLlamaCpp(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/models", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ApplyModelInput is submitted by the Setup Wizard (Web UI or CLI).
type ApplyModelInput struct {
	Name                string `json:"name"`
	Provider            string `json:"provider"`
	Endpoint            string `json:"endpoint"`
	Model               string `json:"model"`
	Tier                int    `json:"tier"`
	Abliterated         bool   `json:"abliterated"`
	AllowRemoteEndpoint bool   `json:"allow_remote_endpoint"`
	APIKey              string `json:"api_key,omitempty"`
}

type ApplyRequest struct {
	Mode              config.Mode       `json:"mode"`
	Strategy          string            `json:"strategy"`
	EscalateThreshold int               `json:"escalate_threshold"`
	Models            []ApplyModelInput `json:"models"`
}

// BuildAndSaveConfig merges wizard choices into baseCfg, stores any API keys in 0600 files
// inside keyDir (never inline in YAML), validates, and atomically writes cfgPath if non-empty.
func BuildAndSaveConfig(baseCfg *config.Config, cfgPath, keyDir string, req ApplyRequest) (*config.Config, error) {
	next := *baseCfg
	if req.Mode != "" {
		next.Mode = req.Mode
	}
	if req.Strategy != "" {
		next.AI.Strategy = req.Strategy
	}
	if req.EscalateThreshold > 0 {
		next.AI.EscalateThreshold = req.EscalateThreshold
	}
	next.AI.Enabled = len(req.Models) > 0
	next.AI.Provider = ""
	next.AI.Endpoint = ""
	next.AI.Model = ""
	next.AI.Models = make([]config.AIModelConfig, 0, len(req.Models))

	type pendingKey struct {
		path string
		val  string
	}
	var keysToWrite []pendingKey

	for i, in := range req.Models {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = fmt.Sprintf("guardian-%d", i+1)
		}
		if !safeSlugRe.MatchString(name) {
			return nil, fmt.Errorf("invalid model name %q (use letters, digits, '-' or '_')", name)
		}

		allowRemote := in.AllowRemoteEndpoint || in.Provider == "venice" || in.Provider == "openrouter"
		mc := config.NormalizeModel(config.AIModelConfig{
			Name:                name,
			Provider:            in.Provider,
			Endpoint:            strings.TrimSpace(in.Endpoint),
			Model:               strings.TrimSpace(in.Model),
			Tier:                in.Tier,
			Abliterated:         in.Abliterated,
			AllowRemoteEndpoint: allowRemote,
			TimeoutSec:          20,
		}, false)

		if key := strings.TrimSpace(in.APIKey); key != "" {
			if keyDir == "" {
				return nil, fmt.Errorf("key directory not configured")
			}
			keyFile := filepath.Join(keyDir, name+".key")
			mc.APIKeyFile = keyFile
			keysToWrite = append(keysToWrite, pendingKey{path: keyFile, val: key})
		}

		if err := config.ValidateModel(mc, false); err != nil {
			return nil, fmt.Errorf("model %q: %w", name, err)
		}
		next.AI.Models = append(next.AI.Models, mc)
	}

	if err := next.Validate(); err != nil {
		return nil, err
	}

	// Only persist secret key files AFTER full validation succeeds, enforcing strict 0600 permissions.
	for _, k := range keysToWrite {
		if err := os.MkdirAll(keyDir, 0o700); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
		f, err := os.OpenFile(k.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open key file: %w", err)
		}
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("chmod key file: %w", err)
		}
		if _, err := f.WriteString(k.val + "\n"); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("write key file: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}

	if cfgPath != "" {
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o750); err != nil {
			return nil, fmt.Errorf("create config dir: %w", err)
		}
		out, err := yaml.Marshal(&next)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		header := []byte("# Generated by Ringwall Setup Wizard\n# API keys are stored separately in 0600 key files — never inside this YAML.\n")
		tmp := cfgPath + ".tmp"
		if err := os.WriteFile(tmp, append(header, out...), 0o640); err != nil {
			return nil, fmt.Errorf("write temp config: %w", err)
		}
		if err := os.Rename(tmp, cfgPath); err != nil {
			return nil, fmt.Errorf("replace config: %w", err)
		}
	}

	return &next, nil
}
