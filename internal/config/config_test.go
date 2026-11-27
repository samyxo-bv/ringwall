// SPDX-License-Identifier: Apache-2.0
package config

import "testing"

func TestConfigRejectsNonLoopbackByDefault(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}

	badAPI := Default()
	badAPI.API.ListenAddr = "0.0.0.0:9443"
	if err := badAPI.Validate(); err == nil {
		t.Fatalf("expected non-loopback API address to be rejected by default")
	}

	badAI := Default()
	badAI.AI.Models = []AIModelConfig{{
		Name:     "remote",
		Provider: "openai",
		Endpoint: "https://api.example.com",
		Model:    "gpt-x",
	}}
	if err := badAI.Validate(); err == nil {
		t.Fatalf("expected remote AI endpoint to be rejected by default")
	}
}
