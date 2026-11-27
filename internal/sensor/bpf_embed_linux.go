// SPDX-License-Identifier: Apache-2.0
//go:build linux && ebpf_embed

package sensor

import _ "embed"

//go:embed ringwall.bpf.o
var embeddedBPF []byte
