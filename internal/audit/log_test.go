// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashChainAndTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := l.Append("incident.created", map[string]any{"id": "inc_1", "action": "freeze"}); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if _, err := l.Append("incident.triaged", map[string]any{"id": "inc_1", "risk": 95}); err != nil {
		t.Fatalf("Append 2: %v", err)
	}

	// Re-open to verify chain continuation across daemon restarts.
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("Re-Open: %v", err)
	}
	if _, err := l2.Append("incident.operator_action", map[string]any{"id": "inc_1", "status": "killed"}); err != nil {
		t.Fatalf("Append 3: %v", err)
	}

	n, err := Verify(path)
	if err != nil || n != 3 {
		t.Fatalf("expected 3 valid entries, got n=%d err=%v", n, err)
	}

	// Tamper with a single character in entry 2.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), `"risk":95`, `"risk":10`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Verify(path); err == nil {
		t.Fatalf("expected Verify to detect tampered entry")
	}
}
