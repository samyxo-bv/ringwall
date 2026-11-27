// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package patcher

type inodeID struct {
	Dev uint64
	Ino uint64
}

func statInodeID(_ string) (inodeID, bool) {
	return inodeID{}, false
}
