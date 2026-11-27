// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var cgroupUnitRe = regexp.MustCompile(`([a-zA-Z0-9@_.-]+\.service)`)

// DetectEcosystem inspects /etc/os-release to build an OSV-compatible ecosystem string
// such as "Debian:12", "Ubuntu:24.04", or "Alpine:v3.20".
func DetectEcosystem(osReleasePath string) string {
	if osReleasePath == "" {
		osReleasePath = "/etc/os-release"
	}
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "Debian:12"
	}
	var id, versionID string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"'`)
		}
	}
	switch strings.ToLower(id) {
	case "debian":
		if versionID != "" {
			return "Debian:" + versionID
		}
		return "Debian"
	case "ubuntu":
		if versionID != "" {
			return "Ubuntu:" + versionID
		}
		return "Ubuntu"
	case "alpine":
		if versionID != "" {
			parts := strings.Split(versionID, ".")
			if len(parts) >= 2 {
				return "Alpine:v" + parts[0] + "." + parts[1]
			}
			return "Alpine:v" + versionID
		}
		return "Alpine"
	default:
		if id != "" {
			return strings.ToUpper(id[:1]) + id[1:]
		}
		return "Linux"
	}
}

// ParseDPKGStatus parses Debian/Ubuntu /var/lib/dpkg/status without invoking external commands.
func ParseDPKGStatus(path, ecosystem string) ([]InstalledPackage, error) {
	if path == "" {
		path = "/var/lib/dpkg/status"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []InstalledPackage
	var cur InstalledPackage
	var installed bool

	flush := func() {
		if installed && cur.Name != "" && cur.Version != "" {
			cur.Ecosystem = ecosystem
			pkgs = append(pkgs, cur)
		}
		cur = InstalledPackage{}
		installed = false
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Name = v
		case "Status":
			installed = strings.Contains(v, "install ok installed")
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Source":
			// Strip optional version suffix: "openssl (3.0.11-1~deb12u2)" -> "openssl"
			if sp := strings.IndexByte(v, ' '); sp > 0 {
				v = v[:sp]
			}
			cur.Source = v
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// ParseAPKInstalled parses Alpine /lib/apk/db/installed cleanly in pure Go.
func ParseAPKInstalled(path, ecosystem string) ([]InstalledPackage, error) {
	if path == "" {
		path = "/lib/apk/db/installed"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []InstalledPackage
	var cur InstalledPackage
	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			cur.Ecosystem = ecosystem
			pkgs = append(pkgs, cur)
		}
		cur = InstalledPackage{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'A':
			cur.Arch = v
		case 'o':
			cur.Source = v
		}
	}
	flush()
	return pkgs, sc.Err()
}

// DetectStaleProcesses inspects /proc/<pid>/maps to find running processes still holding
// deleted shared libraries or binaries (the post-patch restart gap, like needrestart).
func DetectStaleProcesses(procRoot string) []StaleProcess {
	if procRoot == "" {
		procRoot = "/proc"
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []StaleProcess
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 1 {
			continue
		}
		pdir := filepath.Join(procRoot, ent.Name())
		mapsBytes, err := os.ReadFile(filepath.Join(pdir, "maps"))
		if err != nil {
			continue
		}
		seen := make(map[string]struct{})
		var deleted []string
		for _, line := range strings.Split(string(mapsBytes), "\n") {
			if !strings.HasSuffix(line, " (deleted)") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			p := strings.TrimSpace(strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)"))
			if !isExecutableOrLibPath(p) {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			deleted = append(deleted, p)
		}
		if len(deleted) == 0 {
			continue
		}
		sort.Strings(deleted)
		commBytes, _ := os.ReadFile(filepath.Join(pdir, "comm"))
		exe, _ := os.Readlink(filepath.Join(pdir, "exe"))
		cgBytes, _ := os.ReadFile(filepath.Join(pdir, "cgroup"))
		out = append(out, StaleProcess{
			PID:          pid,
			Comm:         strings.TrimSpace(string(commBytes)),
			Exe:          strings.TrimSuffix(exe, " (deleted)"),
			SystemdUnit:  extractSystemdUnit(string(cgBytes)),
			DeletedFiles: deleted,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// ActiveProcessArtifacts collects lowercased basenames and paths of live running executables
// and mapped shared libraries so vulnerability findings can be flagged as actively exposed.
func ActiveProcessArtifacts(procRoot string) map[string][]string {
	if procRoot == "" {
		procRoot = "/proc"
	}
	// token -> list of full exe/lib paths
	active := make(map[string][]string)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return active
	}
	add := func(fullPath string) {
		p := strings.TrimSuffix(strings.TrimSpace(fullPath), " (deleted)")
		if !strings.HasPrefix(p, "/") {
			return
		}
		base := strings.ToLower(filepath.Base(p))
		// Normalize libfoo.so.1.2 -> libfoo and foo
		tok := base
		if idx := strings.Index(tok, ".so"); idx > 0 {
			tok = tok[:idx]
		}
		if tok == "" {
			return
		}
		for _, prev := range active[tok] {
			if prev == p {
				return
			}
		}
		if len(active[tok]) < 4 {
			active[tok] = append(active[tok], p)
		}
	}

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(ent.Name()); err != nil {
			continue
		}
		pdir := filepath.Join(procRoot, ent.Name())
		if exe, err := os.Readlink(filepath.Join(pdir, "exe")); err == nil {
			add(exe)
		}
		if mapsBytes, err := os.ReadFile(filepath.Join(pdir, "maps")); err == nil {
			for _, line := range strings.Split(string(mapsBytes), "\n") {
				if !strings.Contains(line, ".so") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 6 {
					add(fields[5])
				}
			}
		}
	}
	return active
}

func isExecutableOrLibPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.HasPrefix(p, "/memfd:") || strings.HasPrefix(p, "/dev/shm/") || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/SYSV") {
		return false
	}
	return strings.Contains(p, ".so") ||
		strings.HasPrefix(p, "/usr/") ||
		strings.HasPrefix(p, "/bin/") ||
		strings.HasPrefix(p, "/sbin/") ||
		strings.HasPrefix(p, "/lib/")
}

func extractSystemdUnit(cgroupText string) string {
	m := cgroupUnitRe.FindStringSubmatch(cgroupText)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}
