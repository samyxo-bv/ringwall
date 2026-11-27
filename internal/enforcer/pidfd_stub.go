// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package enforcer

import (
	"errors"
	"syscall"
)

var (
	ErrPIDRecycled      = errors.New("process start time changed; refusing to signal recycled PID")
	ErrMissingStartTime = errors.New("process start time unknown (0); refusing unverified PID signal")
)

type osSignaler struct{}

func (osSignaler) SignalVerified(pid int, expectedStartTime uint64, sig syscall.Signal) error {
	if expectedStartTime == 0 {
		return ErrMissingStartTime
	}
	return syscall.Kill(pid, sig)
}

func TryFreezeCgroup(_ int) (string, bool) { return "", false }
func ThawCgroup(_ string) error           { return nil }
