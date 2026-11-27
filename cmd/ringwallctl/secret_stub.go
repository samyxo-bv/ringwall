// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package main

import (
	"bufio"
	"fmt"
	"strings"
)

func readSecretPrompt(in *bufio.Reader, prompt string) string {
	fmt.Printf("%s: ", prompt)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}
