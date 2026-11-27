// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultOSVBaseURL  = "https://api.osv.dev"
	DefaultCISAKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	maxFeedResponseLen = 16 << 20 // 16 MiB cap
)

type kevEntry struct {
	CVEID                      string `json:"cveID"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type kevCatalog struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

func fetchCISAKEV(ctx context.Context, client *http.Client, feedURL string) (map[string]bool, map[string]bool, error) {
	if err := validateHTTPSFeedURL(feedURL); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Ringwall-Scanner/0.2")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("CISA KEV HTTP %d", resp.StatusCode)
	}
	var cat kevCatalog
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFeedResponseLen)).Decode(&cat); err != nil {
		return nil, nil, fmt.Errorf("decode CISA KEV: %w", err)
	}
	inKEV := make(map[string]bool, len(cat.Vulnerabilities))
	ransom := make(map[string]bool, 256)
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if id == "" {
			continue
		}
		inKEV[id] = true
		if strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known") {
			ransom[id] = true
		}
	}
	return inKEV, ransom, nil
}

type osvQuery struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type osvBatchReq struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVulnDetail struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func queryOSV(ctx context.Context, client *http.Client, baseURL string, pkgs []InstalledPackage) ([]Finding, bool, error) {
	if err := validateHTTPSFeedURL(baseURL); err != nil {
		return nil, false, err
	}
	baseURL = strings.TrimRight(baseURL, "/")

	const batchSize = 500
	type hit struct {
		pkg InstalledPackage
		id  string
	}
	var hits []hit
	uniqueIDs := make(map[string]struct{})

	for start := 0; start < len(pkgs); start += batchSize {
		end := start + batchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[start:end]
		reqBody := osvBatchReq{Queries: make([]osvQuery, len(chunk))}
		for i, p := range chunk {
			q := osvQuery{Version: p.Version}
			q.Package.Name = p.Name
			q.Package.Ecosystem = p.Ecosystem
			reqBody.Queries[i] = q
		}
		payload, err := json.Marshal(reqBody)
		if err != nil {
			return nil, false, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/querybatch", bytes.NewReader(payload))
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Ringwall-Scanner/0.2")
		resp, err := client.Do(req)
		if err != nil {
			return nil, false, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxFeedResponseLen))
		resp.Body.Close()
		if readErr != nil {
			return nil, false, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return nil, false, fmt.Errorf("OSV querybatch HTTP %d", resp.StatusCode)
		}
		var br osvBatchResp
		if err := json.Unmarshal(body, &br); err != nil {
			return nil, false, fmt.Errorf("decode OSV querybatch: %w", err)
		}
		for i, res := range br.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range res.Vulns {
				if v.ID == "" {
					continue
				}
				hits = append(hits, hit{pkg: chunk[i], id: v.ID})
				uniqueIDs[v.ID] = struct{}{}
			}
		}
	}

	// Deterministic sorted fetch order; mark truncated=true if capped so auto-revoke fails closed.
	sortedIDs := make([]string, 0, len(uniqueIDs))
	for id := range uniqueIDs {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	const maxDetailFetch = 150
	truncated := len(sortedIDs) > maxDetailFetch
	if truncated {
		sortedIDs = sortedIDs[:maxDetailFetch]
	}

	details := make(map[string]osvVulnDetail, len(sortedIDs))
	for _, id := range sortedIDs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/vulns/"+url.PathEscape(id), nil)
		if err != nil {
			truncated = true
			continue
		}
		req.Header.Set("User-Agent", "Ringwall-Scanner/0.2")
		resp, err := client.Do(req)
		if err != nil {
			truncated = true
			continue
		}
		if resp.StatusCode == http.StatusOK {
			var d osvVulnDetail
			if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&d) == nil {
				details[id] = d
			} else {
				truncated = true
			}
		} else {
			truncated = true
		}
		resp.Body.Close()
	}

	findings := make([]Finding, 0, len(hits))
	for _, h := range hits {
		d := details[h.id]
		cve := extractCVE(h.id, d.Aliases)
		fixed := extractFixedVersion(d, h.pkg.Name, h.pkg.Ecosystem)
		sev := extractSeverity(d)
		sum := strings.TrimSpace(d.Summary)
		if sum == "" {
			sum = fmt.Sprintf("Vulnerability %s affecting %s %s", h.id, h.pkg.Name, h.pkg.Version)
		}
		findings = append(findings, Finding{
			ID:               h.id,
			CVE:              cve,
			Package:          h.pkg.Name,
			Ecosystem:        h.pkg.Ecosystem,
			InstalledVersion: h.pkg.Version,
			FixedVersion:     fixed,
			HasUpstreamFix:   fixed != "",
			Severity:         sev,
			Summary:          sum,
			SourceFeed:       "osv",
		})
	}
	return findings, truncated, nil
}

func loadOfflineBundle(path string) (*OfflineBundle, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle OfflineBundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("parse offline advisory bundle %s: %w", path, err)
	}
	return &bundle, nil
}

func extractCVE(id string, aliases []string) string {
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return strings.ToUpper(id)
	}
	for _, a := range aliases {
		up := strings.ToUpper(strings.TrimSpace(a))
		if strings.HasPrefix(up, "CVE-") {
			return up
		}
	}
	return ""
}

func extractFixedVersion(d osvVulnDetail, pkgName, ecosystem string) string {
	for _, aff := range d.Affected {
		if aff.Package.Name != "" && aff.Package.Name != pkgName {
			continue
		}
		// Match exact release ecosystem (e.g. Debian:12 != Debian:11).
		if aff.Package.Ecosystem != "" && ecosystem != "" && !strings.EqualFold(aff.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

func extractSeverity(d osvVulnDetail) string {
	if d.DatabaseSpecific != nil {
		if raw, ok := d.DatabaseSpecific["severity"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(raw)) {
			case "critical":
				return "critical"
			case "high":
				return "high"
			case "moderate", "medium":
				return "medium"
			case "low":
				return "low"
			}
		}
	}
	for _, s := range d.Severity {
		score := strings.ToUpper(s.Score)
		// Parse direct numeric CVSS or infer high/critical from CVSS3 vector metrics.
		if f, err := strconv.ParseFloat(score, 64); err == nil {
			switch {
			case f >= 9.0:
				return "critical"
			case f >= 7.0:
				return "high"
			case f >= 4.0:
				return "medium"
			default:
				return "low"
			}
		}
		if strings.Contains(score, "AV:N") && strings.Contains(score, "C:H") && strings.Contains(score, "I:H") && strings.Contains(score, "A:H") {
			if strings.Contains(score, "PR:N") && strings.Contains(score, "UI:N") {
				return "critical"
			}
			return "high"
		}
	}
	return "medium"
}

func validateHTTPSFeedURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid feed URL %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	// Allow plain HTTP strictly for loopback unit tests.
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return fmt.Errorf("remote vulnerability feed %q must use https", raw)
}

// CompareVersions performs a lightweight Debian/semver-aware version comparison (<0 if a<b, 0 if a==b, >0 if a>b).
func CompareVersions(a, b string) int {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return 0
	}
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	ta := tokenizeVersion(ra)
	tb := tokenizeVersion(rb)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		var sa, sb string
		if i < len(ta) {
			sa = ta[i]
		}
		if i < len(tb) {
			sb = tb[i]
		}
		if sa == sb {
			continue
		}
		// Tilde (~) and semver prerelease tags (-rc, -alpha, -beta) sort strictly before release.
		isPre := func(s string) bool {
			sl := strings.ToLower(s)
			return strings.HasPrefix(sl, "~") || sl == "rc" || sl == "alpha" || sl == "beta" || sl == "pre"
		}
		if isPre(sa) && !isPre(sb) {
			return -1
		}
		if !isPre(sa) && isPre(sb) {
			return 1
		}
		na, erra := strconv.ParseInt(sa, 10, 64)
		nb, errb := strconv.ParseInt(sb, 10, 64)
		if erra == nil && errb == nil {
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
			continue
		}
		if sa < sb {
			return -1
		}
		return 1
	}
	return 0
}

func splitEpoch(v string) (int, string) {
	if idx := strings.IndexByte(v, ':'); idx > 0 {
		if e, err := strconv.Atoi(v[:idx]); err == nil {
			return e, v[idx+1:]
		}
	}
	return 0, v
}

func tokenizeVersion(v string) []string {
	var out []string
	var cur strings.Builder
	curIsDigit := false
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if ch == '.' || ch == '-' || ch == '+' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		if ch == '~' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			cur.WriteByte('~')
			curIsDigit = false
			continue
		}
		isDig := ch >= '0' && ch <= '9'
		if cur.Len() > 0 && isDig != curIsDigit && cur.String() != "~" {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteByte(ch)
		curIsDigit = isDig
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
