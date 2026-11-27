// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

// Options configures the deterministic CVE, KEV, stale-library, and drift scanner.
type Options struct {
	AllowOnlineFeeds bool
	OSVBaseURL       string
	CISAKEVURL       string
	OfflineDBPath    string
	OSReleasePath    string
	DPKGStatusPath   string
	APKInstalledPath string
	ProcRoot         string
	ProcSysRoot      string
	TokenFile        string
	AuditLogPath     string
	HTTPClient       *http.Client
}

// Scanner performs deterministic host inventory, CVE/KEV correlation, stale-library detection,
// and kernel/file-permission drift auditing.
type Scanner struct {
	opts Options
}

func New(opts Options) *Scanner {
	if opts.OSVBaseURL == "" {
		opts.OSVBaseURL = DefaultOSVBaseURL
	}
	if opts.CISAKEVURL == "" {
		opts.CISAKEVURL = DefaultCISAKEVURL
	}
	if opts.OSReleasePath == "" {
		opts.OSReleasePath = "/etc/os-release"
	}
	if opts.DPKGStatusPath == "" {
		opts.DPKGStatusPath = "/var/lib/dpkg/status"
	}
	if opts.APKInstalledPath == "" {
		opts.APKInstalledPath = "/lib/apk/db/installed"
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.ProcSysRoot == "" {
		opts.ProcSysRoot = "/proc/sys"
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Scanner{opts: opts}
}

func (s *Scanner) Scan(ctx context.Context) ScanReport {
	start := time.Now()
	eco := DetectEcosystem(s.opts.OSReleasePath)
	rep := ScanReport{
		ScannedAt:     start.UTC(),
		Ecosystem:     eco,
		KernelRelease: readKernelRelease(s.opts.ProcRoot),
		Findings:      []Finding{},
		Drift:         []DriftItem{},
		StaleProcesses: []StaleProcess{},
	}

	pkgs, err := ParseDPKGStatus(s.opts.DPKGStatusPath, eco)
	if err != nil {
		if apkPkgs, apkErr := ParseAPKInstalled(s.opts.APKInstalledPath, eco); apkErr == nil {
			pkgs = apkPkgs
		}
	}
	rep.PackageCount = len(pkgs)

	// Detect running executables/libs for exposure scoring and stale deleted libs for restart tracking.
	activeArtifacts := ActiveProcessArtifacts(s.opts.ProcRoot)
	rep.StaleProcesses = DetectStaleProcesses(s.opts.ProcRoot)
	rep.Drift = AuditDrift(s.opts.ProcSysRoot, s.opts.TokenFile, s.opts.AuditLogPath)

	kevSet := make(map[string]bool)
	ransomSet := make(map[string]bool)

	if s.opts.AllowOnlineFeeds {
		rep.OnlineFeedsUsed = true
		if k, r, kerr := fetchCISAKEV(ctx, s.opts.HTTPClient, s.opts.CISAKEVURL); kerr == nil {
			kevSet = k
			ransomSet = r
		} else {
			rep.FeedErrors = append(rep.FeedErrors, "cisa_kev: "+kerr.Error())
		}
		if len(pkgs) > 0 {
			if osvFindings, oerr := queryOSV(ctx, s.opts.HTTPClient, s.opts.OSVBaseURL, pkgs); oerr == nil {
				rep.Findings = append(rep.Findings, osvFindings...)
			} else {
				rep.FeedErrors = append(rep.FeedErrors, "osv: "+oerr.Error())
			}
		}
	}

	// Merge offline deterministic advisory DB (supports airgapped environments and E2E testing).
	if s.opts.OfflineDBPath != "" {
		bundle, berr := loadOfflineBundle(s.opts.OfflineDBPath)
		if berr != nil {
			rep.FeedErrors = append(rep.FeedErrors, "offline_db: "+berr.Error())
		} else if bundle != nil {
			rep.OfflineDBLoaded = true
			rep.Findings = append(rep.Findings, matchOfflineAdvisories(pkgs, bundle.Advisories)...)
		}
	}

	// Deduplicate, enrich KEV/exposure, and assign remediation lanes.
	dedup := make(map[string]int, len(rep.Findings))
	final := make([]Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.CVE != "" {
			if kevSet[strings.ToUpper(f.CVE)] {
				f.InKEV = true
			}
			if ransomSet[strings.ToUpper(f.CVE)] {
				f.RansomwareUse = true
			}
		}
		if f.Severity == "" {
			f.Severity = "medium"
		}
		bins := matchRunningArtifacts(f.Package, f.RunningBins, activeArtifacts)
		if len(bins) > 0 {
			f.Exposed = true
			f.RunningBins = bins
		}
		f.Lane = classifyLane(f)

		key := f.Package + "|" + f.ID
		if f.CVE != "" {
			key = f.Package + "|" + f.CVE
		}
		if idx, exists := dedup[key]; exists {
			// Prefer stronger signal (KEV / exposed / upstream fix metadata).
			if f.InKEV {
				final[idx].InKEV = true
			}
			if f.Exposed {
				final[idx].Exposed = true
			}
			if final[idx].FixedVersion == "" && f.FixedVersion != "" {
				final[idx].FixedVersion = f.FixedVersion
				final[idx].HasUpstreamFix = true
			}
			final[idx].Lane = classifyLane(final[idx])
			continue
		}
		dedup[key] = len(final)
		final = append(final, f)
	}

	rep.Findings = final
	for _, f := range rep.Findings {
		if f.InKEV {
			rep.KEVCount++
		}
		switch f.Lane {
		case LaneImmediatePatch:
			rep.ImmediateCount++
		case LaneVirtualPatch:
			rep.VirtualCount++
		case LaneScheduledPatch:
			rep.ScheduledCount++
		}
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep
}

func matchOfflineAdvisories(pkgs []InstalledPackage, advs []OfflineAdvisory) []Finding {
	byName := make(map[string][]InstalledPackage, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], p)
		if p.Source != "" && p.Source != p.Name {
			byName[p.Source] = append(byName[p.Source], p)
		}
	}

	var out []Finding
	for _, adv := range advs {
		matchedPkgs := byName[adv.Package]
		for _, p := range matchedPkgs {
			if adv.Ecosystem != "" && !strings.HasPrefix(strings.ToLower(p.Ecosystem), strings.ToLower(adv.Ecosystem)) {
				continue
			}
			if adv.FixedVersion != "" && CompareVersions(p.Version, adv.FixedVersion) >= 0 {
				continue // Already patched!
			}
			id := adv.ID
			if id == "" {
				id = adv.CVE
			}
			cve := adv.CVE
			if cve == "" && strings.HasPrefix(strings.ToUpper(id), "CVE-") {
				cve = strings.ToUpper(id)
			}
			out = append(out, Finding{
				ID:               id,
				CVE:              cve,
				Package:          p.Name,
				Ecosystem:        p.Ecosystem,
				InstalledVersion: p.Version,
				FixedVersion:     adv.FixedVersion,
				HasUpstreamFix:   adv.FixedVersion != "",
				Severity:         strings.ToLower(strings.TrimSpace(adv.Severity)),
				InKEV:            adv.InKEV,
				RansomwareUse:    adv.RansomwareUse,
				RunningBins:      append([]string(nil), adv.AffectedBins...),
				Summary:          adv.Summary,
				SourceFeed:       "offline_db",
			})
		}
	}
	return out
}

func matchRunningArtifacts(pkg string, hints []string, active map[string][]string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, h := range hints {
		add(h)
	}
	pLower := strings.ToLower(pkg)
	if paths, ok := active[pLower]; ok {
		for _, p := range paths {
			add(p)
		}
	}
	// Strip numeric ABI suffix (e.g. libssl3 -> libssl).
	trimmed := strings.TrimRight(pLower, "0123456789")
	if trimmed != "" && trimmed != pLower {
		if paths, ok := active[trimmed]; ok {
			for _, p := range paths {
				add(p)
			}
		}
	}
	return out
}

func classifyLane(f Finding) PatchLane {
	sev := strings.ToLower(f.Severity)
	if !f.HasUpstreamFix {
		if f.InKEV || sev == "critical" || sev == "high" {
			return LaneVirtualPatch
		}
		return LaneScheduledPatch
	}
	if f.InKEV || sev == "critical" || (sev == "high" && f.Exposed) {
		return LaneImmediatePatch
	}
	return LaneScheduledPatch
}

func readKernelRelease(procRoot string) string {
	b, err := os.ReadFile(procRoot + "/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
