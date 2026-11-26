// SPDX-License-Identifier: Apache-2.0
package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samyxo-bv/ringwall/internal/config"
)

func TestBuildAndSaveConfigStoresAPIKeyInSeparateFile(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "ringwall.yaml")
	keyDir := filepath.Join(tmp, "keys")

	secret := "venice_test_secret_key_1234567890"
	base := config.Default()

	saved, err := BuildAndSaveConfig(base, cfgPath, keyDir, ApplyRequest{
		Mode:     config.ModeInteractive,
		Strategy: "tiered",
		Models: []ApplyModelInput{
			{
				Name:        "venice-primary",
				Provider:    "venice",
				Model:       "venice-uncensored-1-2",
				Tier:        1,
				Abliterated: true,
				APIKey:      secret,
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildAndSaveConfig: %v", err)
	}

	yamlBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile yaml: %v", err)
	}
	if strings.Contains(string(yamlBytes), secret) {
		t.Fatalf("SECURITY VIOLATION: plaintext API key leaked into ringwall.yaml!")
	}
	if !strings.Contains(string(yamlBytes), "venice-primary.key") {
		t.Fatalf("expected api_key_file reference in ringwall.yaml, got:\n%s", string(yamlBytes))
	}

	resolved, err := config.ResolveAPIKey(saved.AI.Models[0])
	if err != nil || resolved != secret {
		t.Fatalf("ResolveAPIKey = (%q, %v), want %q", resolved, err, secret)
	}
}

func TestBuildAndSaveConfigRejectsPathTraversalModelName(t *testing.T) {
	tmp := t.TempDir()
	_, err := BuildAndSaveConfig(config.Default(), filepath.Join(tmp, "ringwall.yaml"), filepath.Join(tmp, "keys"), ApplyRequest{
		Mode: config.ModeInteractive,
		Models: []ApplyModelInput{
			{Name: "../escape", Provider: "venice", Model: "venice-uncensored-1-2", APIKey: "x"},
		},
	})
	if err == nil {
		t.Fatalf("expected path traversal model name to be rejected")
	}
}

func TestProviderCatalogComplete(t *testing.T) {
	cat := ProviderCatalog()
	if len(cat) < 4 {
		t.Fatalf("expected at least 4 providers in catalog, got %d", len(cat))
	}
	ids := map[string]bool{}
	for _, p := range cat {
		ids[p.ID] = true
		if len(p.RecommendedModels) == 0 || p.Summary == "" {
			t.Errorf("provider %s missing summary or recommended models", p.ID)
		}
	}
	for _, want := range []string{"ollama", "venice", "openrouter", "openai"} {
		if !ids[want] {
			t.Errorf("expected provider %q in catalog", want)
		}
	}
}
