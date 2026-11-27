// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforcer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/samyxo-bv/ringwall/internal/lineage"
)

var (
	ErrPIDRecycled      = errors.New("process start time changed; refusing to signal recycled PID")
	ErrMissingStartTime = errors.New("process start time unknown (0); refusing unverified PID signal")
)

type osSignaler struct{}

// SignalVerified opens a kernel pidfd, strictly requires expectedStartTime > 0, verifies
// /proc/<pid>/stat starttime still matches (defeating PID-reuse races), and signals via pidfd_send_signal.
func (osSignaler) SignalVerified(pid int, expectedStartTime uint64, sig syscall.Signal) error {
	if expectedStartTime == 0 {
		return ErrMissingStartTime
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			if cur, ok := lineage.ReadProcessStartTime(pid); !ok || cur != expectedStartTime {
				return ErrPIDRecycled
			}
			return syscall.Kill(pid, sig)
		}
		return err
	}
	defer unix.Close(fd)

	cur, ok := lineage.ReadProcessStartTime(pid)
	if !ok || cur != expectedStartTime {
		return ErrPIDRecycled
	}
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}

func TryFreezeCgroup(pid int) (string, bool) {
	if pid <= 1 {
		return "", false
	}
	targetCg, ok := readCgroupV2Path(pid)
	if !ok || targetCg == "" || targetCg == "/" || targetCg == "/init.scope" {
		return "", false
	}
	selfCg, _ := readCgroupV2Path(os.Getpid())
	if selfCg != "" && (targetCg == selfCg || strings.HasPrefix(selfCg, targetCg+"/")) {
		return "", false
	}
	if !isIsolatedWorkloadCgroup(targetCg) {
		return "", false
	}
	freezeFile := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(targetCg, "/"), "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("1\n"), 0o644); err != nil {
		return "", false
	}
	return freezeFile, true
}

func ThawCgroup(freezeFile string) error {
	if freezeFile == "" {
		return nil
	}
	if !strings.HasPrefix(freezeFile, "/sys/fs/cgroup/") || !strings.HasSuffix(freezeFile, "/cgroup.freeze") {
		return fmt.Errorf("invalid cgroup freeze path %q", freezeFile)
	}
	return os.WriteFile(freezeFile, []byte("0\n"), 0o644)
}

func readCgroupV2Path(pid int) (string, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimSpace(strings.TrimPrefix(line, "0::")), true
		}
	}
	return "", false
}

func isIsolatedWorkloadCgroup(cgPath string) bool {
	low := strings.ToLower(cgPath)
	if strings.Contains(low, "session-") && !strings.Contains(low, "ringwall-agent") {
		return false
	}
	for _, marker := range []string{"ringwall-agent", "docker", "podman", "containerd", "kubepods", "sandbox"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}
