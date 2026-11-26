// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"timestamp"`
	Kind      string          `json:"kind"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
	Payload   json.RawMessage `json:"payload"`
}

// Log writes a tamper-evident SHA-256 hash-chained JSONL audit log.
type Log struct {
	mu       sync.Mutex
	path     string
	seq      uint64
	lastHash string
}

func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}
	l := &Log{
		path:     path,
		lastHash: genesisHash,
	}
	if _, err := os.Stat(path); err == nil {
		seq, lastHash, err := readChainTail(path)
		if err != nil {
			return nil, fmt.Errorf("read existing audit log tail: %w", err)
		}
		l.seq = seq
		l.lastHash = lastHash
	}
	return l, nil
}

func (l *Log) Append(kind string, payload any) (Entry, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal audit payload: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := Entry{
		Seq:       l.seq,
		Timestamp: now,
		Kind:      kind,
		PrevHash:  l.lastHash,
		Payload:   raw,
	}
	e.Hash = computeHash(e)

	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return Entry{}, fmt.Errorf("open audit log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return Entry{}, fmt.Errorf("write audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return Entry{}, fmt.Errorf("sync audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return Entry{}, err
	}

	l.lastHash = e.Hash
	return e, nil
}

func computeHash(e Entry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|", e.Seq, e.Timestamp.UTC().Format(time.RFC3339Nano), e.Kind, e.PrevHash)
	h.Write(e.Payload)
	return hex.EncodeToString(h.Sum(nil))
}

func readChainTail(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, genesisHash, err
	}
	defer f.Close()

	var seq uint64
	last := genesisHash
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return 0, "", err
		}
		seq = e.Seq
		last = e.Hash
	}
	return seq, last, sc.Err()
}

// Verify checks every single entry in the hash chain and returns an error on any tampering.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prev := genesisHash
	var expectedSeq uint64 = 1
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return count, fmt.Errorf("line %d invalid json: %w", count+1, err)
		}
		if e.Seq != expectedSeq {
			return count, fmt.Errorf("sequence mismatch at line %d: got %d want %d", count+1, e.Seq, expectedSeq)
		}
		if e.PrevHash != prev {
			return count, fmt.Errorf("broken hash chain at seq %d: prev_hash mismatch", e.Seq)
		}
		want := computeHash(e)
		if e.Hash != want {
			return count, fmt.Errorf("tampered entry at seq %d: hash mismatch", e.Seq)
		}
		prev = e.Hash
		expectedSeq++
		count++
	}
	if err := sc.Err(); err != nil {
		return count, err
	}
	return count, nil
}
