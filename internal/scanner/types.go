// SPDX-License-Identifier: Apache-2.0
package scanner

import "time"

// PatchLane classifies how urgently and by which mechanism a vulnerability should be remediated.
type PatchLane string

const (
	LaneImmediatePatch PatchLane = "immediate_patch" // Upstream fix exists + KEV or exposed Critical
	LaneVirtualPatch   PatchLane = "virtual_patch"   // Zero-day / no upstream fix yet (temporary containment)
	LaneScheduledPatch PatchLane = "scheduled_patch" // Upstream fix exists, lower urgency
	LaneDriftFix       PatchLane = "drift_fix"       // Local sysctl / permission hardening drift
)

// InstalledPackage represents a package detected from dpkg or apk local databases.
type InstalledPackage struct {
	Name      string `json:"name"`
	Source    string `json:"source,omitempty"`
	Version   string `json:"version"`
	Arch      string `json:"arch,omitempty"`
	Ecosystem string `json:"ecosystem"` // e.g. "Debian:12", "Ubuntu:24.04", "Alpine:v3.20"
}

// StaleProcess represents a running process still mapping deleted binaries or shared libraries
// after a package upgrade (the classic post-patch restart gap).
type StaleProcess struct {
	PID          int      `json:"pid"`
	Comm         string   `json:"comm"`
	Exe          string   `json:"exe,omitempty"`
	SystemdUnit  string   `json:"systemd_unit,omitempty"`
	DeletedFiles []string `json:"deleted_files"`
}

// Finding is a single prioritized vulnerability finding on this host.
type Finding struct {
	ID               string    `json:"id"` // CVE-YYYY-NNNNN or OSV ID
	CVE              string    `json:"cve,omitempty"`
	Package          string    `json:"package"`
	Ecosystem        string    `json:"ecosystem"`
	InstalledVersion string    `json:"installed_version"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	HasUpstreamFix   bool      `json:"has_upstream_fix"`
	Severity         string    `json:"severity"` // critical | high | medium | low
	InKEV            bool      `json:"in_kev"`
	RansomwareUse    bool      `json:"ransomware_use,omitempty"`
	Exposed          bool      `json:"exposed"`
	RunningBins      []string  `json:"running_bins,omitempty"`
	Summary          string    `json:"summary"`
	Lane             PatchLane `json:"lane"`
	SourceFeed       string    `json:"source_feed"` // osv | offline_db
}

// DriftItem represents a live kernel/filesystem security posture regression.
type DriftItem struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"` // sysctl | file_perm | listener
	Target      string `json:"target"`
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	Severity    string `json:"severity"`
	AutoFixable bool   `json:"auto_fixable"`
	Description string `json:"description"`
}

// ScanReport is the full output of one deterministic security posture & CVE scan.
type ScanReport struct {
	ScannedAt       time.Time      `json:"scanned_at"`
	DurationMS      int64          `json:"duration_ms"`
	Ecosystem       string         `json:"ecosystem"`
	KernelRelease   string         `json:"kernel_release,omitempty"`
	PackageCount    int            `json:"package_count"`
	Findings        []Finding      `json:"findings"`
	Drift           []DriftItem    `json:"drift"`
	StaleProcesses  []StaleProcess `json:"stale_processes"`
	ImmediateCount  int            `json:"immediate_count"`
	VirtualCount    int            `json:"virtual_count"`
	ScheduledCount  int            `json:"scheduled_count"`
	KEVCount        int            `json:"kev_count"`
	FeedErrors      []string       `json:"feed_errors,omitempty"`
	OfflineDBLoaded bool           `json:"offline_db_loaded"`
	OnlineFeedsUsed bool           `json:"online_feeds_used"`
}

// OfflineAdvisory is a deterministic local vulnerability entry used for airgapped hosts and testing.
type OfflineAdvisory struct {
	ID            string   `json:"id"`
	CVE           string   `json:"cve,omitempty"`
	Package       string   `json:"package"`
	Ecosystem     string   `json:"ecosystem,omitempty"`     // optional prefix match (e.g. "Debian")
	FixedVersion  string   `json:"fixed_version,omitempty"` // empty => true 0-day / unpatched
	Severity      string   `json:"severity"`
	InKEV         bool     `json:"in_kev"`
	RansomwareUse bool     `json:"ransomware_use,omitempty"`
	Summary       string   `json:"summary"`
	AffectedBins  []string `json:"affected_bins,omitempty"` // optional hint for virtual patching
}

// OfflineBundle is the JSON file schema loaded from scanner.offline_db_path.
type OfflineBundle struct {
	UpdatedAt  string            `json:"updated_at,omitempty"`
	Advisories []OfflineAdvisory `json:"advisories"`
}
