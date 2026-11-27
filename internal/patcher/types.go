// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"time"

	"github.com/samyxo-bv/ringwall/internal/model"
)

// Mode controls how aggressively the self-healing engine remediates CVEs and drift.
type Mode string

const (
	ModeOff          Mode = "off"           // Scan only; never patch or install virtual rules automatically
	ModeVirtualOnly  Mode = "virtual_only"  // Install temporary virtual containment patches for unpatched 0-days; do not run apt
	ModeAutoCritical Mode = "auto_critical" // Auto-patch KEV/Critical CVEs with upstream fix + virtual-patch 0-days + fix drift
	ModeAutoAll      Mode = "auto_all"      // Auto-patch all CVEs with upstream fix + virtual-patch 0-days + fix drift
)

// VirtualPatch represents a temporary, TTL-bounded declarative containment rule for an unpatched 0-day/CVE.
// Security invariant: virtual patches are strictly declarative Ringwall rules (never raw shell or C code)
// and pass through hard anti-lockout validation before activation.
type VirtualPatch struct {
	ID              string       `json:"id"`
	CVE             string       `json:"cve"`
	Package         string       `json:"package"`
	TargetExePaths  []string     `json:"target_exe_paths,omitempty"`
	TargetPathGlobs []string     `json:"target_path_globs,omitempty"`
	TargetPorts     []uint16     `json:"target_ports,omitempty"`
	Action          model.Action `json:"action"` // freeze | block_egress | kill
	Rationale       string       `json:"rationale"`
	Source          string       `json:"source"` // deterministic | ai_assisted | operator
	CreatedAt       time.Time    `json:"created_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
	KernelLSMActive bool         `json:"kernel_lsm_active,omitempty"`
}

// PackagePatchOutcome records a single security-only package upgrade action.
type PackagePatchOutcome struct {
	Package       string `json:"package"`
	CVE           string `json:"cve,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	Status        string `json:"status"` // patched | dry_run | skipped | failed
	Detail        string `json:"detail,omitempty"`
}

// ServiceRestartOutcome records a post-patch restart of a service holding deleted libraries.
type ServiceRestartOutcome struct {
	Unit   string `json:"unit"`
	Status string `json:"status"` // restarted | skipped_protected | dry_run | failed
	Detail string `json:"detail,omitempty"`
}

// DriftFixOutcome records remediation of a sysctl or file-permission drift item.
type DriftFixOutcome struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Status string `json:"status"` // fixed | dry_run | failed
	Detail string `json:"detail,omitempty"`
}

// ApplySummary summarizes one self-healing remediation cycle.
type ApplySummary struct {
	RunAt                  time.Time               `json:"run_at"`
	Mode                   Mode                    `json:"mode"`
	DryRun                 bool                    `json:"dry_run"`
	PackageResults         []PackagePatchOutcome   `json:"package_results"`
	ServiceRestarts        []ServiceRestartOutcome `json:"service_restarts"`
	DriftFixes             []DriftFixOutcome       `json:"drift_fixes"`
	VirtualPatchesApplied  []VirtualPatch          `json:"virtual_patches_applied"`
	VirtualPatchesRevoked  []string                `json:"virtual_patches_revoked"`
	VirtualPatchesRejected []string                `json:"virtual_patches_rejected,omitempty"`
}

// ABManifest is an Ed25519-signed immutable appliance image release descriptor.
type ABManifest struct {
	Version            string   `json:"version"`
	MinVersion         string   `json:"min_version,omitempty"`
	ReleaseURL         string   `json:"release_url"`
	ImageSHA256        string   `json:"image_sha256"`
	ImageSize          int64    `json:"image_size"`
	CVEsFixed          []string `json:"cves_fixed,omitempty"`
	PublishedAt        string   `json:"published_at"`
	SignatureEd25519B64 string  `json:"signature_ed25519_b64"`
}

// ABSlotState persists the atomic A/B boot-slot state and boot-counter for automatic rollback.
type ABSlotState struct {
	ActiveSlot        string    `json:"active_slot"`          // "A" | "B"
	LastKnownGoodSlot string    `json:"last_known_good_slot"` // "A" | "B"
	PendingSlot       string    `json:"pending_slot,omitempty"`
	TriesRemaining    int       `json:"tries_remaining"`
	CurrentVersion    string    `json:"current_version"`
	PendingVersion    string    `json:"pending_version,omitempty"`
	HealthConfirmed   bool      `json:"health_confirmed"`
	RolledBackFrom    string    `json:"rolled_back_from,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}
