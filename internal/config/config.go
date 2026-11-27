// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeAudit       Mode = "audit"
	ModeInteractive Mode = "interactive"
	ModeStrict      Mode = "strict"
)

type Config struct {
	Mode         Mode           `yaml:"mode"`
	PolicyDirs   []string       `yaml:"policy_dirs"`
	AuditLogPath string         `yaml:"audit_log_path"`
	Sensor       SensorConfig   `yaml:"sensor"`
	Enforcer     EnforcerConfig `yaml:"enforcer"`
	AI           AIConfig       `yaml:"ai"`
	API          APIConfig      `yaml:"api"`
	Scanner      ScannerConfig  `yaml:"scanner"`
	Patcher      PatcherConfig  `yaml:"patcher"`
}

type SensorConfig struct {
	Mode              string `yaml:"mode"` // auto | ebpf | procfs | none
	BPFObjectPath     string `yaml:"bpf_object_path"`
	PollIntervalMS    int    `yaml:"poll_interval_ms"`
	EnableLSMBlocking bool   `yaml:"enable_lsm_blocking"`
}

type ScannerConfig struct {
	Enabled          bool   `yaml:"enabled" json:"enabled"`
	IntervalMin      int    `yaml:"interval_min" json:"interval_min"`
	AllowOnlineFeeds bool   `yaml:"allow_online_feeds" json:"allow_online_feeds"`
	OSVBaseURL       string `yaml:"osv_base_url,omitempty" json:"osv_base_url,omitempty"`
	CISAKEVURL       string `yaml:"cisa_kev_url,omitempty" json:"cisa_kev_url,omitempty"`
	OfflineDBPath    string `yaml:"offline_db_path,omitempty" json:"offline_db_path,omitempty"`
}

type ABUpdateConfig struct {
	Enabled               bool   `yaml:"enabled" json:"enabled"`
	TrustedPubKeyEd25519  string `yaml:"trusted_pubkey_ed25519_b64,omitempty" json:"trusted_pubkey_ed25519_b64,omitempty"`
	StatePath             string `yaml:"state_path,omitempty" json:"state_path,omitempty"`
	BootEnvPath           string `yaml:"boot_env_path,omitempty" json:"boot_env_path,omitempty"`
	SlotAPath             string `yaml:"slot_a_path,omitempty" json:"slot_a_path,omitempty"`
	SlotBPath             string `yaml:"slot_b_path,omitempty" json:"slot_b_path,omitempty"`
}

type PatcherConfig struct {
	Mode                 string         `yaml:"mode" json:"mode"` // off | virtual_only | auto_critical | auto_all
	DryRun               bool           `yaml:"dry_run" json:"dry_run"`
	AutoFixDrift         bool           `yaml:"auto_fix_drift" json:"auto_fix_drift"`
	RestartStaleServices bool           `yaml:"restart_stale_services" json:"restart_stale_services"`
	AIVirtualPatch       bool           `yaml:"ai_virtual_patch" json:"ai_virtual_patch"`
	VirtualPatchFile     string         `yaml:"virtual_patch_file,omitempty" json:"virtual_patch_file,omitempty"`
	ABUpdate             ABUpdateConfig `yaml:"ab_update" json:"ab_update"`
}

type EnforcerConfig struct {
	EnableSignals  bool   `yaml:"enable_signals"`
	EnableNFTables bool   `yaml:"enable_nftables"`
	NFTTable       string `yaml:"nft_table"`
	DryRun         bool   `yaml:"dry_run"`
}

// AIModelConfig configures a single local or explicitly opted-in remote uncensored model.
// API keys are referenced via APIKeyEnv or APIKeyFile (mode 0600) — never stored inline in YAML.
type AIModelConfig struct {
	Name                string `yaml:"name" json:"name"`
	Provider            string `yaml:"provider" json:"provider"` // ollama | openai | venice | openrouter
	Endpoint            string `yaml:"endpoint" json:"endpoint"`
	Model               string `yaml:"model" json:"model"`
	Tier                int    `yaml:"tier" json:"tier"` // 1 = fast triage, 2 = deep second-opinion
	Abliterated         bool   `yaml:"abliterated" json:"abliterated"`
	TimeoutSec          int    `yaml:"timeout_sec" json:"timeout_sec"`
	AllowRemoteEndpoint bool   `yaml:"allow_remote_endpoint,omitempty" json:"allow_remote_endpoint,omitempty"`
	APIKeyEnv           string `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	APIKeyFile          string `yaml:"api_key_file,omitempty" json:"api_key_file,omitempty"`
}

type AIConfig struct {
	Enabled             bool            `yaml:"enabled" json:"enabled"`
	Strategy            string          `yaml:"strategy" json:"strategy"`                     // failover | tiered | consensus
	EscalateThreshold   int             `yaml:"escalate_threshold" json:"escalate_threshold"` // risk score >= N invokes tier 2
	Provider            string          `yaml:"provider,omitempty" json:"provider,omitempty"`
	Endpoint            string          `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Model               string          `yaml:"model,omitempty" json:"model,omitempty"`
	TimeoutSec          int             `yaml:"timeout_sec,omitempty" json:"timeout_sec,omitempty"`
	AllowRemoteEndpoint bool            `yaml:"allow_remote_endpoint,omitempty" json:"allow_remote_endpoint,omitempty"`
	Models              []AIModelConfig `yaml:"models,omitempty" json:"models,omitempty"`
}

type APIConfig struct {
	ListenAddr       string `yaml:"listen_addr"`
	TokenFile        string `yaml:"token_file"`
	AllowNonLoopback bool   `yaml:"allow_non_loopback"`
}

func DefaultEndpointForProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ollama":
		return "http://127.0.0.1:11434"
	case "venice":
		return "https://api.venice.ai/api/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "openai":
		return "http://127.0.0.1:8080"
	default:
		return ""
	}
}

func Default() *Config {
	return &Config{
		Mode:         ModeInteractive,
		PolicyDirs:   []string{"/etc/ringwall/policies.d"},
		AuditLogPath: "/var/log/ringwall/audit.jsonl",
		Sensor: SensorConfig{
			Mode:              "auto",
			BPFObjectPath:     "/usr/lib/ringwall/ringwall.bpf.o",
			PollIntervalMS:    250,
			EnableLSMBlocking: true,
		},
		Enforcer: EnforcerConfig{
			EnableSignals:  true,
			EnableNFTables: false,
			NFTTable:       "inet ringwall",
			DryRun:         false,
		},
		AI: AIConfig{
			Enabled:           true,
			Strategy:          "tiered",
			EscalateThreshold: 55,
			Models: []AIModelConfig{
				{
					Name:        "local-abliterated-fast",
					Provider:    "ollama",
					Endpoint:    "http://127.0.0.1:11434",
					Model:       "huihui_ai/qwen2.5-coder-abliterated:7b",
					Tier:        1,
					Abliterated: true,
					TimeoutSec:  15,
				},
			},
		},
		API: APIConfig{
			ListenAddr:       "127.0.0.1:9443",
			TokenFile:        "/run/ringwall/api.token",
			AllowNonLoopback: false,
		},
		Scanner: ScannerConfig{
			Enabled:          true,
			IntervalMin:      60,
			AllowOnlineFeeds: false,
		},
		Patcher: PatcherConfig{
			Mode:                 "virtual_only",
			DryRun:               false,
			AutoFixDrift:         true,
			RestartStaleServices: true,
			AIVirtualPatch:       true,
			VirtualPatchFile:     "/var/lib/ringwall/virtual-patches.json",
			ABUpdate: ABUpdateConfig{
				Enabled:     false,
				StatePath:   "/var/lib/ringwall/ab-state.json",
				BootEnvPath: "/var/lib/ringwall/ab-boot.env",
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, cfg.Validate()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg.AI.Models = nil
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// EffectiveModels returns normalized AI model entries (multi-model pool or legacy shorthand).
func (a *AIConfig) EffectiveModels() []AIModelConfig {
	if !a.Enabled || a.Provider == "disabled" {
		return nil
	}
	if len(a.Models) > 0 {
		out := make([]AIModelConfig, len(a.Models))
		copy(out, a.Models)
		for i := range out {
			out[i] = NormalizeModel(out[i], a.AllowRemoteEndpoint)
		}
		return out
	}
	if a.Provider != "" && a.Model != "" {
		m := AIModelConfig{
			Name:                a.Model,
			Provider:            a.Provider,
			Endpoint:            a.Endpoint,
			Model:               a.Model,
			Tier:                1,
			TimeoutSec:          a.TimeoutSec,
			AllowRemoteEndpoint: a.AllowRemoteEndpoint,
		}
		return []AIModelConfig{NormalizeModel(m, a.AllowRemoteEndpoint)}
	}
	return nil
}

func NormalizeModel(m AIModelConfig, globalAllowRemote bool) AIModelConfig {
	m.Provider = strings.ToLower(strings.TrimSpace(m.Provider))
	if m.Endpoint == "" {
		m.Endpoint = DefaultEndpointForProvider(m.Provider)
	}
	if m.Tier <= 0 {
		m.Tier = 1
	}
	if m.TimeoutSec <= 0 {
		m.TimeoutSec = 15
	}
	if m.Name == "" {
		m.Name = m.Model
	}
	if globalAllowRemote {
		m.AllowRemoteEndpoint = true
	}
	return m
}

// ResolveAPIKey loads a model's API key from APIKeyEnv or APIKeyFile without ever logging it.
func ResolveAPIKey(m AIModelConfig) (string, error) {
	if m.APIKeyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(m.APIKeyEnv)); v != "" {
			return v, nil
		}
	}
	if m.APIKeyFile != "" {
		b, err := os.ReadFile(m.APIKeyFile)
		if err != nil {
			return "", fmt.Errorf("read api_key_file %s: %w", m.APIKeyFile, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

func ValidateModel(m AIModelConfig, globalAllowRemote bool) error {
	m = NormalizeModel(m, globalAllowRemote)
	switch m.Provider {
	case "ollama", "openai", "venice", "openrouter":
	default:
		return fmt.Errorf("invalid provider %q (expected ollama, openai, venice, or openrouter)", m.Provider)
	}
	if strings.TrimSpace(m.Model) == "" {
		return fmt.Errorf("model ID is required")
	}
	u, err := url.Parse(m.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid endpoint %q", m.Endpoint)
	}
	if !m.AllowRemoteEndpoint && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("endpoint %q is non-loopback; set allow_remote_endpoint: true to opt in to cloud API egress", m.Endpoint)
	}
	if !isLoopbackHost(u.Hostname()) && u.Scheme != "https" {
		return fmt.Errorf("remote endpoint %q must use https", m.Endpoint)
	}
	return nil
}

func (c *Config) Validate() error {
	switch c.Mode {
	case ModeAudit, ModeInteractive, ModeStrict:
	default:
		return fmt.Errorf("invalid mode %q (expected audit, interactive, or strict)", c.Mode)
	}

	switch c.Sensor.Mode {
	case "auto", "ebpf", "procfs", "none":
	default:
		return fmt.Errorf("invalid sensor.mode %q (expected auto, ebpf, procfs, or none)", c.Sensor.Mode)
	}
	if c.Sensor.PollIntervalMS < 50 {
		c.Sensor.PollIntervalMS = 50
	}

	if c.API.ListenAddr != "" {
		host, _, err := net.SplitHostPort(c.API.ListenAddr)
		if err != nil {
			return fmt.Errorf("invalid api.listen_addr %q: %w", c.API.ListenAddr, err)
		}
		if !c.API.AllowNonLoopback && !isLoopbackHost(host) {
			return fmt.Errorf("api.listen_addr %q must be loopback unless api.allow_non_loopback is true", c.API.ListenAddr)
		}
	}

	if c.AI.Strategy == "" {
		c.AI.Strategy = "tiered"
	}
	switch c.AI.Strategy {
	case "failover", "tiered", "consensus":
	default:
		return fmt.Errorf("invalid ai.strategy %q (expected failover, tiered, or consensus)", c.AI.Strategy)
	}
	if c.AI.EscalateThreshold <= 0 {
		c.AI.EscalateThreshold = 55
	}

	if c.AI.Enabled && c.AI.Provider != "disabled" {
		for i, m := range c.AI.EffectiveModels() {
			if err := ValidateModel(m, c.AI.AllowRemoteEndpoint); err != nil {
				return fmt.Errorf("ai.models[%d]: %w", i, err)
			}
		}
	}

	if c.Scanner.IntervalMin <= 0 {
		c.Scanner.IntervalMin = 60
	}
	if c.Patcher.Mode == "" {
		c.Patcher.Mode = "virtual_only"
	}
	switch c.Patcher.Mode {
	case "off", "virtual_only", "auto_critical", "auto_all":
	default:
		return fmt.Errorf("invalid patcher.mode %q (expected off, virtual_only, auto_critical, or auto_all)", c.Patcher.Mode)
	}

	return nil
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
