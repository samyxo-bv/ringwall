// SPDX-License-Identifier: Apache-2.0
package daemon

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/patcher"
	"github.com/samyxo-bv/ringwall/internal/scanner"
	"github.com/samyxo-bv/ringwall/internal/sensor"
)

var vpSafeIDRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func (d *Daemon) initSelfHealing(cfg *config.Config) {
	if cfg == nil {
		return
	}
	sc := scanner.New(scanner.Options{
		AllowOnlineFeeds: cfg.Scanner.AllowOnlineFeeds,
		OSVBaseURL:       cfg.Scanner.OSVBaseURL,
		CISAKEVURL:       cfg.Scanner.CISAKEVURL,
		OfflineDBPath:    cfg.Scanner.OfflineDBPath,
		TokenFile:        cfg.API.TokenFile,
		AuditLogPath:     cfg.AuditLogPath,
	})

	var blocker patcher.KernelBlocker
	if ctrl, ok := d.sensor.(sensor.LSMController); ok {
		blocker = ctrl
	}

	d.selfHealMu.Lock()
	d.scanner = sc
	if d.vpatches == nil {
		d.vpatches = patcher.NewVirtualPatchManager(d.policy, blocker, cfg.Patcher.VirtualPatchFile)
	}
	d.abUpdater = &patcher.ABUpdater{
		StatePath:      cfg.Patcher.ABUpdate.StatePath,
		BootEnvPath:    cfg.Patcher.ABUpdate.BootEnvPath,
		SlotAPath:      cfg.Patcher.ABUpdate.SlotAPath,
		SlotBPath:      cfg.Patcher.ABUpdate.SlotBPath,
		TrustedPubKey:  cfg.Patcher.ABUpdate.TrustedPubKeyEd25519,
		CurrentVersion: d.version,
	}
	d.selfHealMu.Unlock()
}

func (d *Daemon) syncLSMEnforce(cfg *config.Config) {
	if cfg == nil || d.sensor == nil {
		return
	}
	ctrl, ok := d.sensor.(sensor.LSMController)
	if !ok {
		return
	}
	enforce := cfg.Mode != config.ModeAudit && cfg.Sensor.EnableLSMBlocking
	if err := ctrl.SetLSMEnforce(enforce); err != nil {
		log.Printf("ringwall: sync lsm enforce=%v failed: %v", enforce, err)
	}
}

func (d *Daemon) confirmStartupABHealth() {
	d.selfHealMu.RLock()
	up := d.abUpdater
	d.selfHealMu.RUnlock()
	if up == nil || up.StatePath == "" {
		return
	}
	st := up.LoadState()
	if st.PendingSlot == "" {
		return
	}
	healthy := d.sensor != nil && d.policy != nil && d.policy.Count() > 0
	next, rolledBack, err := up.ConfirmBootHealth(healthy)
	if err != nil {
		log.Printf("ringwall: A/B boot health confirmation failed: %v", err)
		return
	}
	kind := "ab.boot_confirmed"
	if rolledBack {
		kind = "ab.rollback_triggered"
	}
	d.recordAudit(kind, next)
}

func (d *Daemon) backgroundSelfHealTick(ctx context.Context) {
	rep := d.RunScan(ctx)
	cfg := d.Config()
	if patcher.Mode(cfg.Patcher.Mode) == patcher.ModeOff {
		return
	}
	if rep.ImmediateCount > 0 || rep.VirtualCount > 0 || len(rep.Drift) > 0 || (patcher.Mode(cfg.Patcher.Mode) == patcher.ModeAutoAll && rep.ScheduledCount > 0) {
		d.RunPatchCycle(ctx, nil)
	}
}

// SetScannerForTest allows deterministic scanner injection in tests.
func (d *Daemon) SetScannerForTest(sc *scanner.Scanner, runner patcher.CmdRunner) {
	d.selfHealMu.Lock()
	defer d.selfHealMu.Unlock()
	d.scanner = sc
	d.cmdRunner = runner
}

// RunScan executes a deterministic host CVE/KEV, stale-library, and drift scan,
// automatically revoking any obsolete virtual patches whose CVE is now resolved.
func (d *Daemon) RunScan(ctx context.Context) scanner.ScanReport {
	d.selfHealMu.RLock()
	sc := d.scanner
	vpMgr := d.vpatches
	d.selfHealMu.RUnlock()
	if sc == nil {
		sc = scanner.New(scanner.Options{})
	}
	rep := sc.Scan(ctx)

	var revoked []string
	if vpMgr != nil {
		revoked = vpMgr.Reconcile(rep.Findings, time.Now().UTC())
	}

	d.selfHealMu.Lock()
	cp := rep
	d.lastScan = &cp
	d.selfHealMu.Unlock()

	d.recordAudit("scanner.completed", map[string]any{
		"ecosystem":        rep.Ecosystem,
		"package_count":    rep.PackageCount,
		"findings":         len(rep.Findings),
		"immediate":        rep.ImmediateCount,
		"virtual_zero_day": rep.VirtualCount,
		"kev_count":        rep.KEVCount,
		"drift_count":      len(rep.Drift),
		"stale_processes":  len(rep.StaleProcesses),
		"revoked_vpatches": revoked,
	})
	d.writePublicStatus()
	return rep
}

func (d *Daemon) LastScan() *scanner.ScanReport {
	d.selfHealMu.RLock()
	defer d.selfHealMu.RUnlock()
	if d.lastScan == nil {
		return nil
	}
	cp := *d.lastScan
	return &cp
}

// RunPatchCycle runs deterministic auto-patching (when enabled), stale-service restarts,
// sysctl/perm drift fixes, and AI/deterministic zero-day virtual patching with strict anti-lockout guardrails.
func (d *Daemon) RunPatchCycle(ctx context.Context, dryRunOverride *bool) patcher.ApplySummary {
	cfg := d.Config()
	mode := patcher.Mode(cfg.Patcher.Mode)
	dryRun := cfg.Patcher.DryRun
	if dryRunOverride != nil {
		dryRun = *dryRunOverride
	}

	rep := d.RunScan(ctx)

	d.selfHealMu.RLock()
	vpMgr := d.vpatches
	runner := d.cmdRunner
	d.selfHealMu.RUnlock()

	summary := patcher.ApplySummary{
		RunAt:                 time.Now().UTC(),
		Mode:                  mode,
		DryRun:                dryRun,
		PackageResults:        []patcher.PackagePatchOutcome{},
		ServiceRestarts:       []patcher.ServiceRestartOutcome{},
		DriftFixes:            []patcher.DriftFixOutcome{},
		VirtualPatchesApplied: []patcher.VirtualPatch{},
		VirtualPatchesRevoked: []string{},
	}

	if mode == patcher.ModeOff && dryRunOverride == nil {
		d.recordAudit("patcher.skipped_off", summary)
		return summary
	}

	// 1. Remediate baseline kernel sysctl / file-permission drift.
	if cfg.Patcher.AutoFixDrift && len(rep.Drift) > 0 {
		summary.DriftFixes = patcher.FixDrift("/proc/sys", rep.Drift, dryRun)
	}

	// 2. Patch packages with upstream fixes (auto_critical: immediate KEV/Critical; auto_all: all).
	if mode == patcher.ModeAutoCritical || mode == patcher.ModeAutoAll {
		var toPatch []scanner.Finding
		for _, f := range rep.Findings {
			if !f.HasUpstreamFix {
				continue
			}
			if f.Lane == scanner.LaneImmediatePatch || (mode == patcher.ModeAutoAll && f.Lane == scanner.LaneScheduledPatch) {
				toPatch = append(toPatch, f)
			}
		}
		if len(toPatch) > 0 {
			summary.PackageResults = patcher.PatchPackages(ctx, runner, toPatch, dryRun)
			if cfg.Patcher.RestartStaleServices {
				stale := scanner.DetectStaleProcesses("/proc")
				if len(stale) == 0 {
					stale = rep.StaleProcesses
				}
				summary.ServiceRestarts = patcher.RestartStaleServices(ctx, runner, stale, dryRun)
			}
		}
	}

	// 3. Zero-day / unpatched CVE Virtual Patching (deterministic + optional uncensored AI proposal).
	if vpMgr != nil && (mode == patcher.ModeVirtualOnly || mode == patcher.ModeAutoCritical || mode == patcher.ModeAutoAll) {
		for _, f := range rep.Findings {
			if f.Lane != scanner.LaneVirtualPatch {
				continue
			}
			vp, err := d.buildVirtualPatchForFinding(ctx, cfg, f)
			if err != nil {
				summary.VirtualPatchesRejected = append(summary.VirtualPatchesRejected, fmt.Sprintf("%s: %v", f.ID, err))
				continue
			}
			if dryRun {
				if verr := patcher.ValidateVirtualPatch(vp); verr != nil {
					summary.VirtualPatchesRejected = append(summary.VirtualPatchesRejected, fmt.Sprintf("%s: %v", vp.ID, verr))
					continue
				}
				summary.VirtualPatchesApplied = append(summary.VirtualPatchesApplied, vp)
				continue
			}
			applied, aerr := vpMgr.Apply(vp)
			if aerr != nil {
				summary.VirtualPatchesRejected = append(summary.VirtualPatchesRejected, fmt.Sprintf("%s: %v", vp.ID, aerr))
				continue
			}
			summary.VirtualPatchesApplied = append(summary.VirtualPatchesApplied, applied)
		}
		summary.VirtualPatchesRevoked = vpMgr.Reconcile(rep.Findings, time.Now().UTC())
	}

	d.selfHealMu.Lock()
	cp := summary
	d.lastPatch = &cp
	d.selfHealMu.Unlock()

	d.recordAudit("patcher.completed", summary)
	d.writePublicStatus()
	return summary
}

func (d *Daemon) buildVirtualPatchForFinding(ctx context.Context, cfg *config.Config, f scanner.Finding) (patcher.VirtualPatch, error) {
	cve := f.CVE
	if cve == "" {
		cve = f.ID
	}
	vpID := "VP-" + vpSafeIDRe.ReplaceAllString(cve, "-")
	if len(vpID) > 64 {
		vpID = vpID[:64]
	}

	// Optional uncensored AI containment proposal — ALWAYS validated by hard deterministic anti-lockout rules.
	if cfg.Patcher.AIVirtualPatch && cfg.AI.Enabled && d.guardian != nil && len(d.guardian.ModelNames()) > 0 {
		if prop, err := d.guardian.ProposeVirtualPatch(ctx, cve, f.Package, f.Summary, f.RunningBins); err == nil && prop != nil {
			now := time.Now().UTC()
			ttl := time.Duration(prop.TTLHours) * time.Hour
			if ttl <= 0 || ttl > patcher.MaxVirtualPatchTTL {
				ttl = patcher.DefaultVirtualPatchTTL
			}
			cand := patcher.VirtualPatch{
				ID:              vpID,
				CVE:             cve,
				Package:         f.Package,
				TargetExePaths:  prop.TargetExePaths,
				TargetPathGlobs: prop.TargetPathGlobs,
				TargetPorts:     prop.TargetPorts,
				Action:          prop.Action,
				Rationale:       strings.TrimSpace(prop.Rationale),
				Source:          "ai_assisted",
				CreatedAt:       now,
				ExpiresAt:       now.Add(ttl),
			}
			if patcher.ValidateVirtualPatch(cand) == nil {
				return cand, nil
			}
		}
	}

	// Deterministic fallback (works 100% offline with zero LLM dependency).
	return patcher.SynthesizeDeterministic(f, patcher.DefaultVirtualPatchTTL)
}

func (d *Daemon) VirtualPatches() []patcher.VirtualPatch {
	d.selfHealMu.RLock()
	vpMgr := d.vpatches
	d.selfHealMu.RUnlock()
	if vpMgr == nil {
		return []patcher.VirtualPatch{}
	}
	return vpMgr.List()
}

func (d *Daemon) ApplyVirtualPatch(vp patcher.VirtualPatch) (patcher.VirtualPatch, error) {
	d.selfHealMu.RLock()
	vpMgr := d.vpatches
	d.selfHealMu.RUnlock()
	if vpMgr == nil {
		return vp, fmt.Errorf("virtual patch manager unavailable")
	}
	if vp.Source == "" {
		vp.Source = "operator"
	}
	applied, err := vpMgr.Apply(vp)
	if err != nil {
		d.recordAudit("virtual_patch.rejected", map[string]any{"id": vp.ID, "error": err.Error()})
		return applied, err
	}
	d.recordAudit("virtual_patch.applied", applied)
	d.writePublicStatus()
	return applied, nil
}

func (d *Daemon) RevokeVirtualPatch(id string) bool {
	d.selfHealMu.RLock()
	vpMgr := d.vpatches
	d.selfHealMu.RUnlock()
	if vpMgr == nil {
		return false
	}
	ok := vpMgr.Revoke(id)
	if ok {
		d.recordAudit("virtual_patch.revoked", map[string]any{"id": id})
		d.writePublicStatus()
	}
	return ok
}

func (d *Daemon) ABStatus() patcher.ABSlotState {
	d.selfHealMu.RLock()
	up := d.abUpdater
	d.selfHealMu.RUnlock()
	if up == nil {
		return patcher.ABSlotState{ActiveSlot: "A", LastKnownGoodSlot: "A", CurrentVersion: d.version, HealthConfirmed: true}
	}
	return up.LoadState()
}

func (d *Daemon) StageABUpdate(ctx context.Context, m patcher.ABManifest) (patcher.ABSlotState, error) {
	d.selfHealMu.RLock()
	up := d.abUpdater
	d.selfHealMu.RUnlock()
	if up == nil {
		return patcher.ABSlotState{}, fmt.Errorf("A/B updater not configured")
	}
	st, err := up.StageUpdate(ctx, m)
	if err != nil {
		d.recordAudit("ab.stage_failed", map[string]any{"version": m.Version, "error": err.Error()})
		return st, err
	}
	d.recordAudit("ab.staged", st)
	return st, nil
}
