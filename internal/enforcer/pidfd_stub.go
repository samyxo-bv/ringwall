// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package enforcer

import (
	"errors"
	"syscall"
)

var ErrPIDRecycled = errors.New("process start time changed; refusing to signal recycled PID")

type osSignaler struct{}

func (osSignaler) SignalVerified(pid int, _ uint64, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

func TryFreezeCgroup(_ int) (string, bool) { return "", false }
func ThawCgroup(_ string) error           { return nil }
