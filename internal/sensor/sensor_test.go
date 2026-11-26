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
	copy(raw.Comm[:], "bash")
	copy(raw.Path[:], "/usr/bin/curl")
	copy(raw.Argv[0][:], "curl")
	copy(raw.Argv[1][:], "-s")
	copy(raw.Argv[2][:], "https://example.invalid/x.sh")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	if buf.Len() != 504 {
		t.Fatalf("expected 504-byte raw struct, got %d", buf.Len())
	}

	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventExec || ev.PID != 1234 || ev.Comm != "bash" || ev.Path != "/usr/bin/curl" {
		t.Fatalf("unexpected decoded exec event: %+v", ev)
	}
	if ev.Cmdline != "curl -s https://example.invalid/x.sh" {
		t.Fatalf("unexpected cmdline: %q", ev.Cmdline)
	}
}

func TestDecodeRawEventConnectIPv4(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventConnect
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
		t.Fatalf("unexpected connect event: %+v", ev)
	}
}

func TestDecodeRawEventOpenWrite(t *testing.T) {
	var raw RawEvent
	raw.Type = rawEventOpenat
	raw.PID = 999
	raw.Flags = 0x0041 // O_WRONLY | O_CREAT
	copy(raw.Comm[:], "python3")
	copy(raw.Path[:], "/etc/cron.d/evil")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	ev, err := DecodeRawEvent(buf.Bytes(), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("DecodeRawEvent: %v", err)
	}
	if ev.Type != model.EventOpen || !ev.IsWrite || ev.Path != "/etc/cron.d/evil" {
		t.Fatalf("unexpected open event: %+v", ev)
	}
}
