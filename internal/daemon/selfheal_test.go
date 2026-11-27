// SPDX-License-Identifier: Apache-2.0
package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/samyxo-bv/ringwall/internal/audit"
	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/enforcer"
	"github.com/samyxo-bv/ringwall/internal/guardian"
	"github.com/samyxo-bv/ringwall/internal/lineage"
	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/scanner"
	"github.com/samyxo-bv/ringwall/internal/sensor"
)

type fakePatchRunner struct {
	cmds [][]string
}

func (f *fakePatchRunner) Run(_ context.Context, _ []string, name string, args ...string) (string, error) {
	f.cmds = append(f.cmds, append([]string{name}, args...))
	if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
		return "active", nil
	}
	return "ok", nil
}

func TestDaemonSelfHealingScanPatchVirtualPatchAndLSMBlockedIncident(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Mode = config.ModeInteractive
	cfg.AuditLogPath = filepath.Join(dir, "audit.jsonl")
	cfg.AI.Enabled = false
	cfg.Patcher.Mode = "auto_critical"
	cfg.Patcher.VirtualPatchFile = filepath.Join(dir, "99-virtual-patches.yaml")
	cfg.Patcher.AutoFixDrift = false // avoid touching host /proc/sys in unit tests

	pol, err := policy.NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	alog, err := audit.Open(cfg.AuditLogPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	sens, _ := sensor.New(config.SensorConfig{Mode: "none"})
	d := New("v0.2.0-test", cfg, sens, lineage.NewTracker(nil), pol, enforcer.New(cfg.Mode, config.EnforcerConfig{DryRun: true}, nil, nil), guardian.New(cfg.AI, nil), alog)

	// Prepare offline dpkg + offline advisory bundle with 1 KEV fixable CVE + 1 unpatched 0-day CVE.
	osRel := filepath.Join(dir, "os-release")
	_ = os.WriteFile(osRel, []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644)
	dpkg := filepath.Join(dir, "status")
	_ = os.WriteFile(dpkg, []byte(`Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u1

Package: vuln-agent-tool
Status: install ok installed
Version: 1.0.0-1
`), 0o644)
	offlineDB := filepath.Join(dir, "advisories.json")
	bundleBytes, _ := json.Marshal(scanner.OfflineBundle{
		Advisories: []scanner.OfflineAdvisory{
			{ID: "CVE-2026-50001", CVE: "CVE-2026-50001", Package: "openssl", FixedVersion: "3.0.11-1~deb12u2", Severity: "critical", InKEV: true, Summary: "Fixable KEV"},
			{ID: "CVE-2026-50002", CVE: "CVE-2026-50002", Package: "vuln-agent-tool", FixedVersion: "", Severity: "critical", InKEV: true, Summary: "Zero-day RCE", AffectedBins: []string{"/usr/bin/vuln-agent-tool"}},
		},
	})
	_ = os.WriteFile(offlineDB, bundleBytes, 0o644)

	sc := scanner.New(scanner.Options{
		OfflineDBPath:  offlineDB,
		OSReleasePath:  osRel,
		DPKGStatusPath: dpkg,
		ProcRoot:       filepath.Join(dir, "empty-proc"),
		ProcSysRoot:    filepath.Join(dir, "empty-procsys"),
	})
	runner := &fakePatchRunner{}
	d.SetScannerForTest(sc, runner)

	summary := d.RunPatchCycle(context.Background(), nil)
	if len(summary.PackageResults) != 1 || summary.PackageResults[0].Status != "patched" || summary.PackageResults[0].Package != "openssl" {
		t.Fatalf("expected openssl auto-patched, got %+v", summary.PackageResults)
	}
	if len(summary.VirtualPatchesApplied) != 1 || summary.VirtualPatchesApplied[0].CVE != "CVE-2026-50002" {
		t.Fatalf("expected 0-day virtual patch applied, got %+v", summary.VirtualPatchesApplied)
	}
	if len(d.VirtualPatches()) != 1 {
		t.Fatalf("expected 1 active virtual patch, got %d", len(d.VirtualPatches()))
	}

	// Verify live virtual patch intercepts execve of /usr/bin/vuln-agent-tool immediately!
	inc := d.ProcessEvent(context.Background(), model.Event{
		Type: model.EventExec, PID: 7777, Comm: "vuln-agent-tool", Exe: "/usr/bin/vuln-agent-tool",
	}, true)
	if inc == nil || len(inc.Matches) != 1 || inc.Matches[0].RuleID != "VP-CVE-2026-50002" {
		t.Fatalf("expected virtual patch incident for vuln-agent-tool, got %+v", inc)
	}

	// Verify synchronous KernelBlocked event (e.g. pinned-inode hardlink read of ~/innocent.txt) records critical incident even with 0 path-glob matches!
	lsmInc := d.ProcessEvent(context.Background(), model.Event{
		Type:          model.EventOpen,
		PID:           8888,
		Comm:          "cat",
		Exe:           "/usr/bin/cat",
		Path:          "/home/operator/hardlink_innocent",
		PathResolved:  true,
		KernelBlocked: true,
	}, true)
	if lsmInc == nil || len(lsmInc.Matches) == 0 || lsmInc.Matches[0].RuleID != "RW-LSM-BLOCK" {
		t.Fatalf("expected RW-LSM-BLOCK incident for kernel-blocked hardlink, got %+v", lsmInc)
	}

	if _, err := audit.Verify(cfg.AuditLogPath); err != nil {
		t.Fatalf("audit chain verify failed: %v", err)
	}
}
