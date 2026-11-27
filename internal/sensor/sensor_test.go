// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/samyxo-bv/ringwall/internal/model"
)

func TestDecodeRawEventExec(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventExec
	raw.PID = 1234
	raw.UID = 1000
	raw.DirFD = -100
	copy(raw.Comm[:], "bash")
	copy(raw.Path[:], "/usr/bin/rm")
	copy(raw.Argv[0][:], "rm")
	copy(raw.Argv[1][:], "-r")
	copy(raw.Argv[2][:], "-f")
	copy(raw.Argv[3][:], "--no-preserve-root")
	copy(raw.Argv[4][:], "/")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	if buf.Len() != 1344 {
		t.Fatalf("expected 1344-byte raw struct matching ringwall.bpf.c, got %d", buf.Len())
	}

	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventExec || ev.PID != 1234 || len(ev.Argv) != 5 {
		t.Fatalf("unexpected decoded exec event: %+v", ev)
	}
	if ev.Cmdline != "rm -r -f --no-preserve-root /" {
		t.Fatalf("unexpected cmdline: %q", ev.Cmdline)
	}
}

func TestDecodeRawEventSendtoIPv4(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventSendto
	raw.PID = 4242
	raw.Family = rawAFInet
	raw.DPort = 4444
	raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3] = 203, 0, 113, 10
	copy(raw.Comm[:], "nc")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventConnect || ev.DstIP != "203.0.113.10" || ev.DstPort != 4444 {
		t.Fatalf("unexpected sendto event: %+v", ev)
	}
}

func TestDecodeRawEventOpenWriteWithDirFD(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventOpenat
	raw.PID = 999
	raw.DirFD = 5
	raw.Flags = 0x0041
	copy(raw.Comm[:], "python3")
	copy(raw.Path[:], "id_ed25519")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventOpen || !ev.IsWrite || ev.DirFD != 5 || ev.Path != "id_ed25519" || ev.PathResolved {
		t.Fatalf("unexpected open event: %+v", ev)
	}
}

func TestDecodeRawEventOpenResolved(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventOpenResolved
	raw.PID = 1001
	raw.DirFD = -100
	raw.Flags = 0
	copy(raw.Comm[:], "python3")
	copy(raw.Path[:], "/home/operator/.ssh/id_ed25519")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventOpen || ev.IsWrite || !ev.PathResolved || ev.Path != "/home/operator/.ssh/id_ed25519" {
		t.Fatalf("unexpected resolved open event: %+v", ev)
	}
}
