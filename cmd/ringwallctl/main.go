// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/audit"
	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/guardian"
	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/setup"
)

var version = "dev"

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:9443", "ringwalld API base URL")
	tokenFile := flag.String("token-file", "/run/ringwall/api.token", "path to bearer token file")
	configFile := flag.String("config", "/etc/ringwall/ringwall.yaml", "path to ringwall.yaml (used by setup/test-ai)")
	jsonOut := flag.Bool("json", false, "output raw JSON")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "version":
		fmt.Printf("ringwallctl %s\n", version)
		return
	case "providers":
		printProviders()
		return
	case "setup":
		runSetupWizard(*configFile)
		return
	case "test-ai":
		runTestAI(*configFile)
		return
	case "verify-log":
		path := "/var/log/ringwall/audit.jsonl"
		if len(args) > 1 {
			path = args[1]
		}
		n, err := audit.Verify(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID audit chain (%d entries checked): %v\n", n, err)
			os.Exit(2)
		}
		fmt.Printf("VALID audit chain (%d entries verified)\n", n)
		return
	case "policy-check":
		dir := "/etc/ringwall/policies.d"
		if len(args) > 1 {
			dir = args[1]
		}
		eng, err := policy.LoadDirs([]string{dir})
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy check failed: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("OK: %d policy rules valid in %s\n", eng.Count(), dir)
		return
	}

	token, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read API token (%s): %v\n", *tokenFile, err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 35 * time.Second}
	base := strings.TrimRight(*apiURL, "/")

	switch cmd {
	case "status":
		body := mustReq(client, http.MethodGet, base+"/api/v1/status", token, nil)
		if *jsonOut {
			fmt.Println(string(body))
			return
		}
		var st model.DaemonStatus
		_ = json.Unmarshal(body, &st)
		fmt.Printf("Ringwall %s\n", st.Version)
		fmt.Printf("  Mode:       %s\n", st.Mode)
		fmt.Printf("  Sensor:     %s\n", st.SensorMode)
		fmt.Printf("  Policies:   %d\n", st.PolicyCount)
		fmt.Printf("  Events:     %d (dropped: %d)\n", st.EventsTotal, st.DroppedEvents)
		fmt.Printf("  Incidents:  %d (frozen: %d)\n", st.IncidentsTotal, st.FrozenCount)
		fmt.Printf("  AI Pool:    enabled=%v strategy=%s models=%v\n", st.AIEnabled, st.AIStrategy, st.AIModels)
		fmt.Printf("  Audit Log:  %s\n", st.AuditLogPath)

	case "incidents":
		body := mustReq(client, http.MethodGet, base+"/api/v1/incidents", token, nil)
		if *jsonOut {
			fmt.Println(string(body))
			return
		}
		var list []model.Incident
		_ = json.Unmarshal(body, &list)
		if len(list) == 0 {
			fmt.Println("No incidents.")
			return
		}
		for _, inc := range list {
			rule := "-"
			if len(inc.Matches) > 0 {
				rule = inc.Matches[0].RuleID
			}
			risk := "-"
			if inc.AI != nil {
				risk = fmt.Sprintf("%d/100", inc.AI.RiskScore)
			}
			fmt.Printf("%-16s %-8s %-8s %-14s pid=%-6d comm=%-10s risk=%-7s %s\n",
				inc.ID, inc.Severity, inc.Status, rule, inc.Event.PID, inc.Event.Comm, risk, inc.EnforcementNote)
		}

	case "simulate":
		body := mustReq(client, http.MethodPost, base+"/api/v1/simulate", token, nil)
		if *jsonOut {
			fmt.Println(string(body))
			return
		}
		var resp struct {
			SimulatedCount int              `json:"simulated_count"`
			Incidents      []model.Incident `json:"incidents"`
		}
		_ = json.Unmarshal(body, &resp)
		fmt.Printf("Simulated %d attack scenarios:\n", resp.SimulatedCount)
		for _, inc := range resp.Incidents {
			sum := ""
			if inc.AI != nil {
				sum = inc.AI.Summary
			}
			fmt.Printf("  [%s] %-8s %-8s det=%-12s eff=%-12s %s\n",
				inc.ID, inc.Severity, inc.Status, inc.DeterministicAction, inc.EffectiveAction, sum)
		}

	case "resume", "approve", "kill":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "usage: ringwallctl %s <incident-id>\n", cmd)
			os.Exit(1)
		}
		payload, _ := json.Marshal(map[string]string{"action": cmd})
		body := mustReq(client, http.MethodPost, base+"/api/v1/incidents/"+args[1]+"/action", token, payload)
		if *jsonOut {
			fmt.Println(string(body))
			return
		}
		var inc model.Incident
		_ = json.Unmarshal(body, &inc)
		fmt.Printf("Updated %s -> status=%s (%s)\n", inc.ID, inc.Status, inc.EnforcementNote)

	default:
		usage()
		os.Exit(1)
	}
}

func printProviders() {
	exp := setup.Explainer()
	fmt.Printf("\n=== %s ===\n%s\n\n%s\n\n", exp["headline"], exp["why"], exp["safety"])
	for i, p := range setup.ProviderCatalog() {
		fmt.Printf("%d) %s [%s]\n", i+1, p.DisplayName, strings.ToUpper(p.Kind))
		fmt.Printf("   Summary:  %s\n", p.Summary)
		fmt.Printf("   Privacy:  %s | Cost: %s | GPU: %s\n", p.Privacy, p.Cost, p.NeedsGPU)
		fmt.Printf("   Endpoint: %s\n", p.DefaultEndpoint)
		fmt.Printf("   Models:   %s\n", strings.Join(p.RecommendedModels, ", "))
		fmt.Printf("   Docs:     %s\n\n", p.DocsURL)
	}
}

func runTestAI(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", cfgPath, err)
		os.Exit(1)
	}
	models := cfg.AI.EffectiveModels()
	if len(models) == 0 {
		fmt.Println("No AI models configured. Run 'ringwallctl setup' to configure an abliterated/uncensored model.")
		os.Exit(1)
	}
	g := guardian.New(cfg.AI, nil)
	allOK := true
	for _, m := range models {
		fmt.Printf("\nTesting model %q (%s / %s)...\n", m.Name, m.Provider, m.Model)
		res := g.TestModel(context.Background(), m, "")
		printCheckResult(res)
		if !res.Passed {
			allOK = false
		}
	}
	if !allOK {
		os.Exit(2)
	}
}

func runSetupWizard(cfgPath string) {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt, def string) string {
		if def != "" {
			fmt.Printf("%s [%s]: ", prompt, def)
		} else {
			fmt.Printf("%s: ", prompt)
		}
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		return line
	}

	exp := setup.Explainer()
	fmt.Println("======================================================================")
	fmt.Println("  RINGWALL GUIDED SETUP WIZARD (No YAML editing required)")
	fmt.Println("======================================================================")
	fmt.Printf("\n%s\n%s\n\n%s\n", exp["headline"], exp["why"], exp["safety"])

	env := setup.DetectEnvironment(context.Background())
	fmt.Printf("\n[Auto-Detected] RAM: %d GB | NVIDIA GPU: %v | Local Ollama: %v\n",
		env.TotalRAMGB, env.HasNVIDIA, env.OllamaRunning)
	fmt.Printf("[Tip] %s\n", env.RecommendedHint)

	fmt.Println("\n--- Step 1: Protection Mode ---")
	fmt.Println("  1) Safe Watch (audit)         - Watch and explain only, never stop apps")
	fmt.Println("  2) Ask Me First (interactive) - Freeze threats and ask you [Recommended]")
	fmt.Println("  3) Lockdown (strict)          - Automatically terminate critical threats")
	mode := config.ModeInteractive
	switch ask("Choose 1, 2, or 3", "2") {
	case "1":
		mode = config.ModeAudit
	case "3":
		mode = config.ModeStrict
	}

	fmt.Println("\n--- Step 2: Choose your Uncensored / Abliterated AI Provider ---")
	cat := setup.ProviderCatalog()
	for i, p := range cat {
		fmt.Printf("  %d) %s\n     %s (GPU: %s | Privacy: %s)\n", i+1, p.DisplayName, p.Summary, p.NeedsGPU, p.Privacy)
	}
	choice := ask("Choose 1-4", "1")
	idx := 0
	if choice == "2" {
		idx = 1
	} else if choice == "3" {
		idx = 2
	} else if choice == "4" {
		idx = 3
	}
	prov := cat[idx]

	fmt.Printf("\nSelected: %s\n", prov.DisplayName)
	for i, step := range prov.QuickSteps {
		fmt.Printf("  %d. %s\n", i+1, step)
	}

	defaultModel := prov.RecommendedModels[0]
	if prov.ID == "ollama" && len(env.OllamaModels) > 0 {
		fmt.Printf("  Detected local Ollama models: %s\n", strings.Join(env.OllamaModels, ", "))
		defaultModel = env.OllamaModels[0]
	}

	endpoint := ask("Endpoint URL", prov.DefaultEndpoint)
	modelID := ask("Model ID", defaultModel)
	apiKey := ""
	if prov.NeedsAPIKey || prov.ID == "openai" {
		if prov.Kind == "cloud" {
			fmt.Println("  [Privacy note] Cloud AI APIs receive redacted incident metadata (command lines with common tokens/keys stripped). For 100% offline privacy, use Local Ollama.")
		}
		apiKey = readSecretPrompt(in, "API Key (input hidden if TTY, stored in 0600 key file; blank if local)")
	}

	fmt.Println("\n--- Step 3: Live 4-Point Security & Refusal Check ---")
	fmt.Println("Sending a safe fake reverse-shell security alert to verify your model does NOT refuse...")
	mc := config.AIModelConfig{
		Name:                prov.ID + "-primary",
		Provider:            prov.ID,
		Endpoint:            endpoint,
		Model:               modelID,
		Tier:                1,
		Abliterated:         true,
		AllowRemoteEndpoint: prov.ID != "ollama",
		TimeoutSec:          25,
	}
	g := guardian.New(config.AIConfig{Enabled: true}, nil)
	res := g.TestModel(context.Background(), mc, apiKey)
	printCheckResult(res)

	if !res.Passed {
		cont := strings.ToLower(ask("The live model check did not pass. Save config anyway? (y/N)", "n"))
		if cont != "y" && cont != "yes" {
			fmt.Println("Aborted without modifying config. Fix the model/API key and run 'ringwallctl setup' again.")
			os.Exit(1)
		}
	}

	baseCfg := config.Default()
	if existing, err := config.Load(cfgPath); err == nil {
		baseCfg = existing
	}

	keyDir := filepath.Join(filepath.Dir(cfgPath), "keys")
	_, err := setup.BuildAndSaveConfig(baseCfg, cfgPath, keyDir, setup.ApplyRequest{
		Mode:              mode,
		Strategy:          "tiered",
		EscalateThreshold: 55,
		Models: []setup.ApplyModelInput{{
			Name:                prov.ID + "-primary",
			Provider:            prov.ID,
			Endpoint:            endpoint,
			Model:               modelID,
			Tier:                1,
			Abliterated:         true,
			AllowRemoteEndpoint: prov.ID != "ollama",
			APIKey:              apiKey,
		}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to save %s: %v\n(Run with sudo if writing to /etc/ringwall)\n", cfgPath, err)
		os.Exit(1)
	}

	fmt.Printf("\nSaved %s cleanly (API keys stored separately with mode 0600).\n", cfgPath)
	fmt.Println("Restart/reload daemon: sudo systemctl restart ringwalld")
	fmt.Println("Verify live:           ringwallctl status && ringwallctl simulate")
}

func printCheckResult(res guardian.ModelCheckResult) {
	mark := func(ok bool) string {
		if ok {
			return "[PASS]"
		}
		return "[FAIL]"
	}
	fmt.Printf("  %s 1. Server / API Key Reachable (%d ms)\n", mark(res.Reachable), res.LatencyMS)
	fmt.Printf("  %s 2. Zero Refusal on Security Telemetry (uncensored check)\n", mark(res.RefusalFree))
	fmt.Printf("  %s 3. Strict JSON Security Verdict Format\n", mark(res.ValidJSON))
	fmt.Printf("  %s 4. Caught Simulated Reverse Shell (risk=%d/100, action=%s)\n", mark(res.ThreatDetected), res.RiskScore, res.RecommendedAction)
	if res.Error != "" {
		fmt.Printf("  Error:   %s\n", res.Error)
	}
	if res.Summary != "" {
		fmt.Printf("  Summary: %s\n", res.Summary)
	}
	fmt.Printf("  Advice:  %s\n", res.Advice)
}

func usage() {
	fmt.Println(`Usage: ringwallctl [flags] <command> [args]

Commands:
  setup                     Interactive beginner-friendly Setup Wizard (local or cloud uncensored AI)
  providers                 Compare local & cloud uncensored/abliterated AI providers
  test-ai                   Run live 4-point API + security refusal test on configured models
  status                    Show daemon, sensor, policy, and AI Guardian status
  incidents                 List recorded security incidents
  simulate                  Run 5 safe built-in attack simulations
  approve <incident-id>     Resume process and add scoped exception
  resume <incident-id>      Resume frozen process once (SIGCONT)
  kill <incident-id>        Terminate process (SIGKILL)
  verify-log [path]         Verify SHA-256 hash-chain integrity of audit log
  policy-check [dir]        Validate YAML policy files
  version                   Print version`)
}

func readToken(path string) (string, error) {
	if env := strings.TrimSpace(os.Getenv("RINGWALL_TOKEN")); env != "" {
		return env, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func mustReq(client *http.Client, method, url, token string, body []byte) []byte {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "API request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "API error (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(data)))
		os.Exit(1)
	}
	return data
}
