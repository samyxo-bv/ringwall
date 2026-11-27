// SPDX-License-Identifier: Apache-2.0
//go:build linux

package patcher

import (
	"os"
	"syscall"
)

type inodeID struct {
	Dev uint64
	Ino uint64
}

func statInodeID(path string) (inodeID, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return inodeID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return inodeID{}, false
	}
	return inodeID{Dev: uint64(st.Dev), Ino: st.Ino}, true
}
