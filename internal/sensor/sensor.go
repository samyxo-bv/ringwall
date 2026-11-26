// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/model"
)

var ErrUnsupportedPlatform = errors.New("sensor unsupported on this platform")

const (
	rawEventExec    uint32 = 1
	rawEventOpenat  uint32 = 2
	rawEventConnect uint32 = 3
	rawEventSendto  uint32 = 4

	rawAFInet  uint16 = 2
	rawAFInet6 uint16 = 10

	openWriteMask uint32 = 0x0001 | 0x0002 | 0x0040 // O_WRONLY | O_RDWR | O_CREAT
)

// RawEvent matches struct ringwall_event in ebpf/ringwall.bpf.c byte-for-byte (1280 bytes).
type RawEvent struct {
	Type   uint32
	PID    uint32
	PPID   uint32
	UID    uint32
	Flags  uint32
	DirFD  int32
	DPort  uint16
	Family uint16
	Pad    uint32
	Addr   [16]byte
	Comm   [16]byte
	Path   [192]byte
	Argv   [8][128]byte
}

// Sensor streams kernel/OS telemetry events into a channel and tracks dropped events.
type Sensor interface {
	Mode() string
	Dropped() uint64
	Start(ctx context.Context, out chan<- model.Event) error
}

// DecodeRawEvent converts a 1280-byte eBPF ringbuf record into a model.Event.
func DecodeRawEvent(data []byte, now time.Time) (model.Event, error) {
	var raw RawEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return model.Event{}, fmt.Errorf("decode raw bpf event: %w", err)
	}

	ev := model.Event{
		Timestamp: now.UTC(),
		PID:       int(raw.PID),
		PPID:      int(raw.PPID),
		UID:       raw.UID,
		DirFD:     raw.DirFD,
		Comm:      cString(raw.Comm[:]),
		Path:      cString(raw.Path[:]),
		Flags:     raw.Flags,
	}

	switch raw.Type {
	case rawEventExec:
		ev.Type = model.EventExec
		ev.Exe = ev.Path
		args := make([]string, 0, 8)
		for i := range raw.Argv {
			if s := cString(raw.Argv[i][:]); s != "" {
				args = append(args, s)
			}
		}
		ev.Argv = args
		if len(args) > 0 {
			ev.Cmdline = strings.Join(args, " ")
		} else {
			ev.Cmdline = ev.Path
		}
	case rawEventOpenat:
		ev.Type = model.EventOpen
		ev.IsWrite = (raw.Flags & openWriteMask) != 0
	case rawEventConnect, rawEventSendto:
		ev.Type = model.EventConnect
		ev.DstPort = raw.DPort
		switch raw.Family {
		case rawAFInet:
			ip := netip.AddrFrom4([4]byte{raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3]})
			ev.DstIP = ip.String()
		case rawAFInet6:
			ip := netip.AddrFrom16(raw.Addr)
			ev.DstIP = ip.String()
		}
	default:
		return model.Event{}, fmt.Errorf("unknown bpf event type %d", raw.Type)
	}

	return ev, nil
}

func cString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		b = b[:idx]
	}
	return string(b)
}

type noopSensor struct{}

func (noopSensor) Mode() string    { return "none" }
func (noopSensor) Dropped() uint64 { return 0 }
func (noopSensor) Start(ctx context.Context, _ chan<- model.Event) error {
	<-ctx.Done()
	return nil
}

func New(cfg config.SensorConfig) (Sensor, error) {
	switch cfg.Mode {
	case "none":
		return noopSensor{}, nil
	case "ebpf":
		return newEBPFSensor(cfg)
	case "procfs":
		return newProcfsSensor(cfg)
	case "auto", "":
		s, err := newEBPFSensor(cfg)
		if err == nil {
			return s, nil
		}
		ps, perr := newProcfsSensor(cfg)
		if perr == nil {
			return ps, nil
		}
		return nil, fmt.Errorf("ebpf failed (%v) and procfs fallback failed (%v)", err, perr)
	default:
		return nil, fmt.Errorf("unsupported sensor mode %q", cfg.Mode)
	}
}
