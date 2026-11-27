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
	synced []string
}

func (f *fakeKernelBlocker) SyncBlockedExecPaths(paths []string) (int, error) {
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

	// Verify stale service restarts skip protected ringwalld.service & sshd.service while restarting nginx.service.
	restarts := RestartStaleServices(context.Background(), fr, []scanner.StaleProcess{
		{PID: 10, SystemdUnit: "ringwalld.service"},
		{PID: 11, SystemdUnit: "sshd.service"},
		{PID: 12, SystemdUnit: "nginx.service"},
	}, false)
	byUnit := map[string]string{}
	for _, r := range restarts {
		byUnit[r.Unit] = r.Status
	}
	if byUnit["ringwalld.service"] != "skipped_protected" || byUnit["sshd.service"] != "skipped_protected" || byUnit["nginx.service"] != "restarted" {
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

func TestVirtualPatchAntiLockoutLiveEnforceAndAutoRevoke(t *testing.T) {
	eng, err := policy.NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	blocker := &fakeKernelBlocker{}
	mgr := NewVirtualPatchManager(eng, blocker, filepath.Join(t.TempDir(), "99-virtual-patches.yaml"))

	// Anti-lockout MUST reject ringwalld, bash, and overbroad /** globs!
	badCases := []VirtualPatch{
		{ID: "VP-BAD-1", CVE: "CVE-1", TargetExePaths: []string{"/usr/local/bin/ringwalld"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-2", CVE: "CVE-2", TargetExePaths: []string{"/usr/bin/bash"}, Action: model.ActionKill, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-3", CVE: "CVE-3", TargetPathGlobs: []string{"/**"}, Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "VP-BAD-4", CVE: "CVE-4", Action: model.ActionFreeze, ExpiresAt: time.Now().Add(time.Hour)}, // empty matchers
	}
	for _, bad := range badCases {
		if _, err := mgr.Apply(bad); err == nil {
			t.Errorf("expected anti-lockout to reject %s", bad.ID)
		}
	}

	// Valid 0-day virtual patch for /usr/sbin/vuln-httpd activates live in policy.Engine AND kernel LSM blocker.
	vp, err := mgr.Apply(VirtualPatch{
		ID:             "VP-CVE-2026-99999",
		CVE:            "CVE-2026-99999",
		Package:        "vuln-httpd",
		TargetExePaths: []string{"/usr/sbin/vuln-httpd"},
		Action:         model.ActionFreeze,
		Source:         "deterministic",
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Apply valid virtual patch: %v", err)
	}
	if !vp.KernelLSMActive || len(blocker.synced) != 1 || blocker.synced[0] != "/usr/sbin/vuln-httpd" {
		t.Fatalf("expected kernel LSM exec blocker synced, got %+v", blocker.synced)
	}

	matches, act, _ := eng.Evaluate(model.Event{Type: model.EventExec, Exe: "/usr/sbin/vuln-httpd", Comm: "vuln-httpd"})
	if len(matches) != 1 || act != model.ActionFreeze {
		t.Fatalf("expected live virtual patch match, got matches=%d act=%s", len(matches), act)
	}

	// Auto-revoke once upstream scan no longer reports CVE-2026-99999.
	revoked := mgr.Reconcile(nil, time.Now().UTC())
	if len(revoked) != 1 || revoked[0] != "VP-CVE-2026-99999" {
		t.Fatalf("expected auto-revocation after CVE resolved, got %v", revoked)
	}
	if matches, _, _ := eng.Evaluate(model.Event{Type: model.EventExec, Exe: "/usr/sbin/vuln-httpd"}); len(matches) != 0 {
		t.Fatalf("revoked virtual patch still matched")
	}
}

func TestSignedABUpdaterVerifyStagePromoteAndAutoRollback(t *testing.T) {
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
	up := &ABUpdater{
		StatePath:      filepath.Join(dir, "ab-state.json"),
		BootEnvPath:    filepath.Join(dir, "ab-boot.env"),
		SlotAPath:      filepath.Join(dir, "slot_a.squashfs"),
		SlotBPath:      filepath.Join(dir, "slot_b.squashfs"),
		TrustedPubKey:  pub,
		CurrentVersion: "v0.1.0",
		HTTPClient:     srv.Client(),
	}

	manifest := ABManifest{
		Version:     "v0.2.0",
		ReleaseURL:  srv.URL + "/ringwall-v0.2.0.squashfs",
		ImageSHA256: imgHash,
		ImageSize:   int64(len(imgPayload)),
		CVEsFixed:   []string{"CVE-2026-88888"},
		PublishedAt: "2026-11-27T06:00:00Z",
	}
	if err := SignManifest(priv, &manifest); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}

	// 1. Tampered manifest MUST fail Ed25519 verification.
	tampered := manifest
	tampered.Version = "v0.2.1"
	if err := VerifyManifest(pub, "v0.1.0", tampered); err == nil {
		t.Fatalf("expected tampered manifest to fail signature check")
	}

	// 2. Downgrade manifest MUST fail anti-downgrade check even if legitimately signed!
	oldM := manifest
	oldM.Version = "v0.0.9"
	_ = SignManifest(priv, &oldM)
	if err := VerifyManifest(pub, "v0.1.0", oldM); err == nil {
		t.Fatalf("expected downgrade manifest to be rejected")
	}

	// 3. Valid stage writes to inactive slot B and arms 2 boot tries.
	st, err := up.StageUpdate(context.Background(), manifest)
	if err != nil {
		t.Fatalf("StageUpdate: %v", err)
	}
	if st.PendingSlot != "B" || st.TriesRemaining != 2 {
		t.Fatalf("unexpected staged state: %+v", st)
	}

	// 4. Two failed boots MUST automatically roll back to LastKnownGoodSlot ("A").
	st, rolled, err := up.ConfirmBootHealth(false)
	if err != nil || rolled || st.TriesRemaining != 1 {
		t.Fatalf("first boot fail should decrement tries to 1, got rolled=%v state=%+v err=%v", rolled, st, err)
	}
	st, rolled, err = up.ConfirmBootHealth(false)
	if err != nil || !rolled || st.ActiveSlot != "A" || st.PendingSlot != "" || st.RolledBackFrom != "v0.2.0" {
		t.Fatalf("second boot fail must auto-rollback to slot A, got rolled=%v state=%+v err=%v", rolled, st, err)
	}

	// 5. Re-stage and confirm healthy boot promotes slot B -> ActiveSlot & LastKnownGoodSlot!
	if _, err := up.StageUpdate(context.Background(), manifest); err != nil {
		t.Fatalf("re-StageUpdate: %v", err)
	}
	st, rolled, err = up.ConfirmBootHealth(true)
	if err != nil || rolled || st.ActiveSlot != "B" || st.LastKnownGoodSlot != "B" || st.CurrentVersion != "v0.2.0" {
		t.Fatalf("expected healthy promotion to slot B v0.2.0, got rolled=%v state=%+v err=%v", rolled, st, err)
	}
}
