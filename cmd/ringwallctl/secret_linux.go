// SPDX-License-Identifier: Apache-2.0
//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readSecretPrompt disables terminal echo when stdin is a TTY so API keys are never echoed on screen.
func readSecretPrompt(in *bufio.Reader, prompt string) string {
	fmt.Printf("%s: ", prompt)
	fd := int(os.Stdin.Fd())
	if oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		noEcho := *oldState
		noEcho.Lflag &^= unix.ECHO
		if unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho) == nil {
			defer func() {
				_ = unix.IoctlSetTermios(fd, unix.TCSETS, oldState)
				fmt.Println()
			}()
		}
	}
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}
