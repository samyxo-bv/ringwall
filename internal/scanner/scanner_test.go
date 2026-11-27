// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareVersionsDebianAndSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u2", 0},
		{"3.0.11-1~deb12u3", "3.0.11-1~deb12u2", 1},
		{"1:4.13-1", "9.0-1", 1}, // epoch wins
		{"2.0~rc1", "2.0", -1},   // tilde sorts before release
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestScanOfflineAndOnlineOSVKEVAndDrift(t *testing.T) {
	dir := t.TempDir()

	// 1. Mock /etc/os-release and /var/lib/dpkg/status
	osRel := filepath.Join(dir, "os-release")
	_ = os.WriteFile(osRel, []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644)

	dpkg := filepath.Join(dir, "status")
	_ = os.WriteFile(dpkg, []byte(`Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u1

Package: curl
Status: install ok installed
Architecture: amd64
Version: 7.88.1-10+deb12u4

Package: already-fixed
Status: install ok installed
Architecture: amd64
Version: 2.0.0-1
`), 0o644)

	// 2. Mock proc/sys drift + insecure token file perm (0644 -> critical drift)
	procSys := filepath.Join(dir, "procsys")
	_ = os.MkdirAll(filepath.Join(procSys, "kernel"), 0o755)
	_ = os.WriteFile(filepath.Join(procSys, "kernel", "kptr_restrict"), []byte("0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procSys, "kernel", "unprivileged_userns_clone"), []byte("1\n"), 0o644)

	tok := filepath.Join(dir, "api.token")
	_ = os.WriteFile(tok, []byte("secret\n"), 0o644)

	// 3. Mock /proc/<pid>/maps with deleted .so library (stale process)
	procRoot := filepath.Join(dir, "proc")
	pDir := filepath.Join(procRoot, "4242")
	_ = os.MkdirAll(pDir, 0o755)
	_ = os.WriteFile(filepath.Join(pDir, "comm"), []byte("nginx\n"), 0o644)
	_ = os.WriteFile(filepath.Join(pDir, "cgroup"), []byte("0::/system.slice/nginx.service\n"), 0o644)
	_ = os.WriteFile(filepath.Join(pDir, "maps"), []byte("7f0000-7f1000 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"), 0o644)

	// 4. Offline advisory bundle with 1 unpatched 0-day (curl) and 1 already-fixed package
	offlinePath := filepath.Join(dir, "offline.json")
	bundle := OfflineBundle{
		Advisories: []OfflineAdvisory{
			{
				ID:           "CVE-2026-99999",
				CVE:          "CVE-2026-99999",
				Package:      "curl",
				Ecosystem:    "Debian",
				FixedVersion: "", // True 0-day: no upstream fix yet!
				Severity:     "critical",
				InKEV:        true,
				Summary:      "Zero-day RCE in curl before upstream patch",
				AffectedBins: []string{"/usr/bin/curl"},
			},
			{
				ID:           "CVE-2026-11111",
				CVE:          "CVE-2026-11111",
				Package:      "already-fixed",
				Ecosystem:    "Debian",
				FixedVersion: "2.0.0-1",
				Severity:     "critical",
				Summary:      "Already patched — must not appear",
			},
		},
	}
	bBytes, _ := json.Marshal(bundle)
	_ = os.WriteFile(offlinePath, bBytes, 0o644)

	// 5. Mock local OSV + CISA KEV HTTP servers (loopback HTTP allowed for tests)
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"DSA-5999-1"}]},{"vulns":[]},{"vulns":[]}]}`))
		case "/v1/vulns/DSA-5999-1":
			_, _ = w.Write([]byte(`{
				"id":"DSA-5999-1",
				"summary":"OpenSSL critical buffer overflow",
				"aliases":["CVE-2026-88888"],
				"database_specific":{"severity":"CRITICAL"},
				"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]}]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer osvSrv.Close()

	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-88888","knownRansomwareCampaignUse":"Known"}]}`))
	}))
	defer kevSrv.Close()

	sc := New(Options{
		AllowOnlineFeeds: true,
		OSVBaseURL:       osvSrv.URL,
		CISAKEVURL:       kevSrv.URL,
		OfflineDBPath:    offlinePath,
		OSReleasePath:    osRel,
		DPKGStatusPath:   dpkg,
		ProcRoot:         procRoot,
		ProcSysRoot:      procSys,
		TokenFile:        tok,
	})

	rep := sc.Scan(context.Background())
	if rep.PackageCount != 3 {
		t.Fatalf("expected 3 installed packages, got %d", rep.PackageCount)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 findings (1 immediate openssl + 1 0-day curl), got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.ImmediateCount != 1 || rep.VirtualCount != 1 || rep.KEVCount != 2 {
		t.Fatalf("unexpected counts: immediate=%d virtual=%d kev=%d", rep.ImmediateCount, rep.VirtualCount, rep.KEVCount)
	}
	if len(rep.StaleProcesses) != 1 || rep.StaleProcesses[0].SystemdUnit != "nginx.service" {
		t.Fatalf("expected nginx.service stale process, got %+v", rep.StaleProcesses)
	}
	if len(rep.Drift) < 2 {
		t.Fatalf("expected sysctl drift items, got %+v", rep.Drift)
	}
}
