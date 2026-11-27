// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samyxo-bv/ringwall/internal/model"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/scanner"
)

type fakeRunner struct {
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, _ []string, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
		return "active", nil
	}
	return "ok", nil
}

type fakeKernelBlocker struct {
	mu     sync.Mutex
	synced []string
}

func (f *fakeKernelBlocker) SyncBlockedExecPaths(paths []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append([]string(nil), paths...)
	return len(paths), nil
}

func TestHostPatcherRejectsInjectionAndProtectsCriticalServices(t *testing.T) {
	fr := &fakeRunner{}
	findings := []scanner.Finding{
		{Package: "openssl", CVE: "CVE-2026-1001", FixedVersion: "3.0.12", HasUpstreamFix: true},
		{Package: "--evil-flag", CVE: "CVE-2026-1002", FixedVersion: "1.0", HasUpstreamFix: true},
		{Package: "foo;rm -rf /", CVE: "CVE-2026-1003", FixedVersion: "1.0", HasUpstreamFix: true},
	}
	res := PatchPackages(context.Background(), fr, findings, false)
	patched, failed := 0, 0
	for _, r := range res {
		switch r.Status {
		case "patched":
			patched++
		case "failed":
			failed++
		}
	}
	if patched != 1 || failed != 2 {
		t.Fatalf("expected 1 patched + 2 rejected, got patched=%d failed=%d: %+v", patched, failed, res)
	}

	// Verify stale service restarts skip ringwalld, sshd, and user@1000 while restarting nginx.
	restarts := RestartStaleServices(context.Background(), fr, []scanner.StaleProcess{
		{PID: 10, SystemdUnit: "ringwalld.service"},
		{PID: 11, SystemdUnit: "sshd.service"},
		{PID: 12, SystemdUnit: "user@1000.service"},
		{PID: 13, SystemdUnit: "nginx.service"},
	}, false)
	byUnit := map[string]string{}
	for _, r := range restarts {
		byUnit[r.Unit] = r.Status
	}
	if byUnit["ringwalld.service"] != "skipped_protected" ||
		byUnit["sshd.service"] != "skipped_protected" ||
		byUnit["user@1000.service"] != "skipped_protected" ||
		byUnit["nginx.service"] != "restarted" {
		t.Fatalf("unexpected restart statuses: %+v", byUnit)
	}
}

func TestDriftAutoRemediation(t *testing.T) {
	dir := t.TempDir()
	procSys := filepath.Join(dir, "procsys")
	_ = os.MkdirAll(filepath.Join(procSys, "kernel"), 0o755)
	kptr := filepath.Join(procSys, "kernel", "kptr_restrict")
	_ = os.WriteFile(kptr, []byte("0\n"), 0o644)

	fixes := FixDrift(procSys, []scanner.DriftItem{
		{ID: "RW-DRIFT-001", Kind: "sysctl", Target: "kernel.kptr_restrict", Expected: "2", Actual: "0", AutoFixable: true},
		{ID: "RW-DRIFT-BAD", Kind: "sysctl", Target: "kernel.evil_unlisted", Expected: "1", Actual: "0", AutoFixable: true},
	}, false)
	if len(fixes) != 2 || fixes[0].Status != "fixed" || fixes[1].Status != "failed" {
		t.Fatalf("unexpected drift fixes: %+v", fixes)
	}
	b, _ := os.ReadFile(kptr)
	if strings.TrimSpace(string(b)) != "2" {
		t.Fatalf("expected kptr_restrict restored to 2, got %q", string(b))
	}
}

func TestVirtualPatchP0AntiLockoutSymlinksAliasesGlobsPortsAndAIKill(t *testing.T) {
	dir := t.TempDir()
	eng, err := policy.NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	blocker := &fakeKernelBlocker{}
	mgr := NewVirtualPatchManager(eng, blocker, filepath.Join(dir, "virtual-patches.json"))

	// Create a real temp protected binary + symlink (simulates /usr/bin/rbash -> /usr/bin/bash).
	fakeBash := filepath.Join(dir, "real-bash")
	_ = os.WriteFile(fakeBash, []byte("#!/bin/sh\n"), 0o755)
	mgr.AddProtectedBinaryForTest(fakeBash)
	fakeRbash := filepath.Join(dir, "rbash-link")
	_ = os.Symlink(fakeBash, fakeRbash)

	badCases := []VirtualPatch{
		{ID: "VP-BAD-1", CVE: "CVE-1", TargetExePaths: []string{"/usr/local/bin/ringwalld"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-2", CVE: "CVE-2", TargetExePaths: []string{"/usr/bin/rbash"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-3", CVE: "CVE-3", TargetExePaths: []string{fakeRbash}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-4", CVE: "CVE-4", TargetExePaths: []string{"/sbin/sshd"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-5", CVE: "CVE-5", TargetExePaths: []string{"/usr/lib/openssh/sshd-session"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-6", CVE: "CVE-6", TargetExePaths: []string{"/bin/apt-get"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-7", CVE: "CVE-7", TargetPathGlobs: []string{"/**/*"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-8", CVE: "CVE-8", TargetPathGlobs: []string{"/usr/**/*"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-9", CVE: "CVE-9", TargetPathGlobs: []string{"/etc/ssh/**"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-10", CVE: "CVE-10", TargetPathGlobs: []string{"/etc/ssh/sshd_config"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-11", CVE: "CVE-11", TargetPathGlobs: []string{"/var/*"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-12", CVE: "CVE-12", TargetPorts: []uint16{22}, Source: "ai_assisted", Action: model.ActionBlockEgress, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-13", CVE: "CVE-13", TargetPorts: []uint16{443}, Source: "ai_assisted", Action: model.ActionBlockEgress, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-14", CVE: "CVE-14", TargetExePaths: []string{"/usr/sbin/vuln-httpd"}, Source: "ai_assisted", Action: model.ActionKill, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-15", CVE: "CVE-15", Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)}, // empty matchers
		// P0-A & P2-7 regressions: login/shell/PAM/sudoers/root/home-dotfile globs & systemd/dbus binaries
		{ID: "VP-BAD-16", CVE: "CVE-16", TargetPathGlobs: []string{"/root/.ssh/authorized_keys"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-17", CVE: "CVE-17", TargetPathGlobs: []string{"/home/operator/.ssh/*"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-18", CVE: "CVE-18", TargetPathGlobs: []string{"/home/operator/.ssh/authorized_keys"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-19", CVE: "CVE-19", TargetPathGlobs: []string{"/home/operator/.profile"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-20", CVE: "CVE-20", TargetPathGlobs: []string{"/home/operator/.bashrc"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-21", CVE: "CVE-21", TargetPathGlobs: []string{"/etc/pam.d/sshd"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-22", CVE: "CVE-22", TargetPathGlobs: []string{"/etc/sudoers.d/local"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-23", CVE: "CVE-23", TargetExePaths: []string{"/usr/lib/systemd/systemd-executor"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-24", CVE: "CVE-24", TargetExePaths: []string{"/usr/bin/dbus-daemon"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
	}
	for _, bad := range badCases {
		if _, err := mgr.Apply(bad); err == nil {
			t.Errorf("P0 REGRESSION: anti-lockout MUST reject %s (%+v)", bad.ID, bad)
		}
	}

	// P0-A RUNTIME INVARIANT: even a valid glob VP must NEVER match/freeze a protected system binary!
	if _, err := mgr.Apply(VirtualPatch{
		ID:              "VP-SAFE-GLOB",
		CVE:             "CVE-2026-44444",
		Package:         "custom-app",
		TargetPathGlobs: []string{"/opt/app/data/*.cfg"},
		Action:          model.ActionFreeze,
		Source:          "ai_assisted",
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Apply valid glob virtual patch: %v", err)
	}
	for _, protExe := range []string{"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/bin/bash", fakeBash} {
		matches, act, _ := eng.Evaluate(model.Event{
			Type: model.EventOpen,
			Exe:  protExe,
			Path: "/opt/app/data/app.cfg",
		})
		if len(matches) != 0 || act != model.ActionAllow {
			t.Fatalf("P0-A REGRESSION: virtual patch matched protected exe %s: matches=%+v act=%s", protExe, matches, act)
		}
	}
	if matches, act, _ := eng.Evaluate(model.Event{
		Type: model.EventOpen,
		Exe:  "/opt/app/bin/worker",
		Path: "/opt/app/data/app.cfg",
	}); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("expected non-protected worker to match virtual patch, got matches=%+v act=%s", matches, act)
	}

	// P1-B SYMLINK-SWAP TOCTOU REGRESSION: replacing a VP target with a symlink to a protected binary
	// after initial Apply MUST exclude that target on the next SyncBlockedExecPaths!
	targetBin := filepath.Join(dir, "user-tool")
	_ = os.WriteFile(targetBin, []byte("#!/bin/sh\n"), 0o755)
	if _, err := mgr.Apply(VirtualPatch{
		ID:             "VP-TOCTOU-TARGET",
		CVE:            "CVE-2026-55555",
		Package:        "user-tool",
		TargetExePaths: []string{targetBin},
		Action:         model.ActionFreeze,
		Source:         "operator",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Apply VP-TOCTOU-TARGET: %v", err)
	}
	if len(blocker.synced) != 1 || blocker.synced[0] != filepath.ToSlash(targetBin) {
		t.Fatalf("expected initial targetBin synced, got %+v", blocker.synced)
	}
	// Attacker replaces targetBin with symlink to protected fakeBash, then triggers another sync:
	_ = os.Remove(targetBin)
	_ = os.Symlink(fakeBash, targetBin)
	mgr.Revoke("VP-SAFE-GLOB")
	for _, s := range blocker.synced {
		if s == filepath.ToSlash(targetBin) {
			t.Fatalf("P1-B REGRESSION: symlink-swapped targetBin was still passed to SyncBlockedExecPaths: %+v", blocker.synced)
		}
	}

	// P1-1 REGRESSION: RefreshAndSync clears unlinked/upgraded targets and preserves protected binaries.
	freshTarget := filepath.Join(dir, "upgrade-target")
	_ = os.WriteFile(freshTarget, []byte("#!/bin/sh\n"), 0o755)
	if _, err := mgr.Apply(VirtualPatch{
		ID:             "VP-UPGRADE-TARGET",
		CVE:            "CVE-2026-55556",
		Package:        "upgrade-target",
		TargetExePaths: []string{freshTarget},
		Action:         model.ActionFreeze,
		Source:         "operator",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Apply VP-UPGRADE-TARGET: %v", err)
	}
	// P2-a REGRESSION: EventExec with non-zero PID pointing to current process must NOT skip target Exe!
	if matches, act, _ := eng.Evaluate(model.Event{
		Type: model.EventExec,
		PID:  os.Getpid(),
		Exe:  filepath.ToSlash(freshTarget),
	}); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("P2-a REGRESSION: EventExec virtual patch was skipped on non-protected target: matches=%+v act=%s", matches, act)
	}
	_ = os.Remove(freshTarget)
	mgr.RefreshAndSync()
	for _, s := range blocker.synced {
		if s == filepath.ToSlash(freshTarget) {
			t.Fatalf("P1-1 REGRESSION: unlinked target still present after RefreshAndSync: %+v", blocker.synced)
		}
	}
}

func TestVirtualPatchFailClosedReconcileAndRestartPersistence(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "virtual-patches.json")
	vulnBin := filepath.Join(dir, "vuln-httpd")
	_ = os.WriteFile(vulnBin, []byte("#!/bin/sh\n"), 0o755)
	vulnBinSlash := filepath.ToSlash(vulnBin)

	eng1, _ := policy.NewEngine(nil)
	blocker1 := &fakeKernelBlocker{}
	mgr1 := NewVirtualPatchManager(eng1, blocker1, storePath)

	_, err := mgr1.Apply(VirtualPatch{
		ID:             "VP-CVE-2026-99999",
		CVE:            "CVE-2026-99999",
		Package:        "vuln-httpd",
		TargetExePaths: []string{vulnBinSlash},
		Action:         model.ActionFreeze,
		Source:         "deterministic",
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Apply valid virtual patch: %v", err)
	}

	// P1-3 REGRESSION CHECK: feed error / incomplete scan MUST NOT auto-revoke active 0-day patch!
	erroredScan := scanner.ScanReport{
		PackageCount: 100,
		Complete:     false,
		FeedErrors:   []string{"osv: connection refused"},
		Findings:     nil,
	}
	if revoked := mgr1.Reconcile(erroredScan, time.Now().UTC()); len(revoked) != 0 {
		t.Fatalf("P1-3 REGRESSION: feed error caused fail-open revocation: %v", revoked)
	}
	if len(mgr1.List()) != 1 {
		t.Fatalf("expected virtual patch preserved across errored scan")
	}

	// P1-4 REGRESSION CHECK: simulate daemon restart with fresh Engine, Blocker, and Manager!
	eng2, _ := policy.NewEngine(nil)
	blocker2 := &fakeKernelBlocker{}
	mgr2 := NewVirtualPatchManager(eng2, blocker2, storePath)
	n, err := mgr2.LoadPersisted()
	if err != nil || n != 1 {
		t.Fatalf("P1-4 REGRESSION: LoadPersisted failed: loaded=%d err=%v", n, err)
	}
	if len(blocker2.synced) != 1 || blocker2.synced[0] != vulnBinSlash {
		t.Fatalf("P1-4 REGRESSION: kernel LSM exec blocker not restored after restart: %+v", blocker2.synced)
	}
	if matches, act, _ := eng2.Evaluate(model.Event{Type: model.EventExec, Exe: vulnBinSlash}); len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("P1-4 REGRESSION: policy rule not active after restart")
	}
	if !mgr2.Revoke("VP-CVE-2026-99999") {
		t.Fatalf("P1-4 REGRESSION: Revoke after restart returned false")
	}
	if len(blocker2.synced) != 0 {
		t.Fatalf("expected kernel blocker cleared after Revoke, got %+v", blocker2.synced)
	}

	// P2-4 REGRESSION CHECK: concurrent Apply/Revoke persist calls must not race or corrupt JSON!
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "VP-CONC-" + string(rune('A'+idx))
			_, _ = mgr2.Apply(VirtualPatch{
				ID:             id,
				CVE:            "CVE-2026-77777",
				Package:        "vuln-httpd",
				TargetExePaths: []string{vulnBinSlash},
				Action:         model.ActionFreeze,
				Source:         "operator",
				ExpiresAt:      time.Now().UTC().Add(time.Hour),
			})
			mgr2.Revoke(id)
		}(i)
	}
	wg.Wait()

	// Re-apply and verify Complete scan (0 errors, positive inventory, CVE resolved) DOES auto-revoke cleanly.
	_, _ = mgr2.Apply(VirtualPatch{
		ID:             "VP-CVE-2026-99999",
		CVE:            "CVE-2026-99999",
		Package:        "vuln-httpd",
		TargetExePaths: []string{vulnBinSlash},
		Action:         model.ActionFreeze,
		Source:         "deterministic",
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	})
	completeClean := scanner.ScanReport{
		PackageCount:    100,
		Complete:        true,
		OfflineDBLoaded: true,
		Findings:        nil,
	}
	if revoked := mgr2.Reconcile(completeClean, time.Now().UTC()); len(revoked) != 1 {
		t.Fatalf("expected auto-revocation on Complete clean scan, got %v", revoked)
	}
}

func TestSignedABUpdaterRequiresRealBootSlotBeforePromotion(t *testing.T) {
	pub, priv, err := GenerateABKeypair()
	if err != nil {
		t.Fatalf("GenerateABKeypair: %v", err)
	}

	imgPayload := []byte("SQUASHFS-HARDENED-RINGWALL-V0.2.0-IMAGE-BYTES")
	sum := sha256.Sum256(imgPayload)
	imgHash := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(imgPayload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	bootedSlot := "A"
	up := &ABUpdater{
		Enabled:        true,
		StatePath:      filepath.Join(dir, "ab-state.json"),
		BootEnvPath:    filepath.Join(dir, "ab-boot.env"),
		SlotAPath:      filepath.Join(dir, "slot_a.squashfs"),
		SlotBPath:      filepath.Join(dir, "slot_b.squashfs"),
		TrustedPubKey:  pub,
		CurrentVersion: "v0.1.0",
		BootedSlotFunc: func() string { return bootedSlot },
		HTTPClient:     srv.Client(),
	}

	manifest := ABManifest{
		Version:     "v0.2.0",
		MinVersion:  "v0.1.0",
		ReleaseURL:  srv.URL + "/ringwall-v0.2.0.squashfs",
		ImageSHA256: imgHash,
		ImageSize:   int64(len(imgPayload)),
		CVEsFixed:   []string{"CVE-2026-88888"},
		PublishedAt: "2026-11-27T06:00:00Z",
	}
	if err := SignManifest(priv, &manifest); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	// 1. Tampered manifest, downgrade, and violated MinVersion MUST fail.
	tampered := manifest
	tampered.Version = "v0.2.1"
	if err := VerifyManifest(pub, "v0.1.0", tampered); err == nil {
		t.Fatalf("expected tampered manifest rejected")
	}
	oldM := manifest
	oldM.Version = "v0.0.9"
	_ = SignManifest(priv, &oldM)
	if err := VerifyManifest(pub, "v0.1.0", oldM); err == nil {
		t.Fatalf("expected downgrade manifest rejected")
	}
	if err := VerifyManifest(pub, "v0.0.5", manifest); err == nil {
		t.Fatalf("expected MinVersion violation rejected")
	}

	// 2. Stage update to slot B.
	st, err := up.StageUpdate(context.Background(), manifest)
	if err != nil || st.PendingSlot != "B" || st.TriesRemaining != 2 {
		t.Fatalf("StageUpdate failed: st=%+v err=%v", st, err)
	}

	// 3. P1-5 REGRESSION CHECK: daemon restart while STILL booted in slot A MUST NOT promote slot B!
	st, rolled, err := up.ConfirmBootHealth(true)
	if err != nil || rolled || st.PendingSlot != "B" || st.ActiveSlot != "A" || st.TriesRemaining != 2 {
		t.Fatalf("P1-5 REGRESSION: daemon restart without reboot falsely promoted unbooted slot B: %+v", st)
	}

	// 4. Now simulate actual reboot into slot B with two failed health checks -> auto-rollback to A!
	bootedSlot = "B"
	st, rolled, err = up.ConfirmBootHealth(false)
	if err != nil || rolled || st.TriesRemaining != 1 {
		t.Fatalf("first boot fail on B should decrement tries to 1, got %+v", st)
	}
	st, rolled, err = up.ConfirmBootHealth(false)
	if err != nil || !rolled || st.ActiveSlot != "A" || st.PendingSlot != "" || st.RolledBackFrom != "v0.2.0" {
		t.Fatalf("second boot fail on B must auto-rollback to A, got rolled=%v st=%+v", rolled, st)
	}

	// 5. Re-stage from A, reboot into B, and confirm healthy boot promotes B!
	bootedSlot = "A"
	if _, err := up.StageUpdate(context.Background(), manifest); err != nil {
		t.Fatalf("re-StageUpdate: %v", err)
	}
	bootedSlot = "B"
	st, rolled, err = up.ConfirmBootHealth(true)
	if err != nil || rolled || st.ActiveSlot != "B" || st.LastKnownGoodSlot != "B" || st.CurrentVersion != "v0.2.0" {
		t.Fatalf("expected healthy promotion to B v0.2.0, got rolled=%v st=%+v", rolled, st)
	}
}

func TestOfficialReleasePubKeyVerifiesV020Manifest(t *testing.T) {
	pubBytes, err := os.ReadFile(filepath.Join("..", "..", "packaging", "ringwall-release.pub"))
	if err != nil {
		t.Fatalf("read official release public key: %v", err)
	}
	pub := strings.TrimSpace(string(pubBytes))
	manifest := ABManifest{
		Version:             "v0.2.0",
		ReleaseURL:          "https://github.com/samyxo-bv/ringwall/releases/download/v0.2.0/ringwall-v0.2.0-appliance-amd64.iso",
		ImageSHA256:         "aa779c1b5e119df6c1b960340fabd88c51df14716ee2f25b936075a04a60e5b9",
		ImageSize:           203780096,
		PublishedAt:         "2026-11-27T09:14:49Z",
		SignatureEd25519B64: "vXQUkUhWIUsJ8vgr/53RV8jesco0TFVjaN6x5me+FuJ9qnbM4uGAhZV5vV3n4h2mZNXNrO3Rkv7cq58YkP4wDg==",
	}
	if err := VerifyManifest(pub, "v0.1.0", manifest); err != nil {
		t.Fatalf("official release pubkey failed to verify v0.2.0 manifest: %v", err)
	}
	tampered := manifest
	tampered.ImageSize++
	if err := VerifyManifest(pub, "v0.1.0", tampered); err == nil {
		t.Fatalf("expected tampered v0.2.0 manifest rejected")
	}
}
