// SPDX-License-Identifier: Apache-2.0
package model

import "time"

type EventType string

const (
	EventExec      EventType = "exec"
	EventOpen      EventType = "open"
	EventConnect   EventType = "connect"
	EventSimulated EventType = "simulated"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

type Action string

const (
	ActionAllow       Action = "allow"
	ActionWarn        Action = "warn"
	ActionFreeze      Action = "freeze"
	ActionBlockEgress Action = "block_egress"
	ActionKill        Action = "kill"
)

// Rank defines strict severity ordering for actions.
// Security invariant: AI triage can NEVER downgrade an action to a lower Rank.
func (a Action) Rank() int {
	switch a {
	case ActionAllow:
		return 0
	case ActionWarn:
		return 1
	case ActionFreeze:
		return 2
	case ActionBlockEgress:
		return 3
	case ActionKill:
		return 4
	default:
		return 0
	}
}

// MaxAction returns the stricter of two actions.
func MaxAction(a, b Action) Action {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     uint32 `json:"uid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
}

type Event struct {
	Timestamp time.Time     `json:"timestamp"`
	Type      EventType     `json:"type"`
	PID       int           `json:"pid"`
	PPID      int           `json:"ppid"`
	UID       uint32        `json:"uid"`
	Comm      string        `json:"comm"`
	Exe       string        `json:"exe,omitempty"`
	Path      string        `json:"path,omitempty"`
	Cmdline   string        `json:"cmdline,omitempty"`
	Flags     uint32        `json:"flags,omitempty"`
	IsWrite   bool          `json:"is_write,omitempty"`
	DstIP     string        `json:"dst_ip,omitempty"`
	DstPort   uint16        `json:"dst_port,omitempty"`
	Ancestry  []ProcessInfo `json:"ancestry,omitempty"`
	Simulated bool          `json:"simulated,omitempty"`
}

type PolicyMatch struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Action      Action   `json:"action"`
	Description string   `json:"description"`
	MITRE       string   `json:"mitre,omitempty"`
}

type ModelVote struct {
	Name              string `json:"name"`
	Model             string `json:"model"`
	Tier              int    `json:"tier"`
	Abliterated       bool   `json:"abliterated,omitempty"`
	RiskScore         int    `json:"risk_score"`
	RecommendedAction Action `json:"recommended_action"`
	Summary           string `json:"summary,omitempty"`
	Reasoning         string `json:"reasoning,omitempty"`
	RefusalDetected   bool   `json:"refusal_detected,omitempty"`
	Error             string `json:"error,omitempty"`
	LatencyMS         int64  `json:"latency_ms"`
}

type AIAnalysis struct {
	Strategy          string      `json:"strategy"`
	Provider          string      `json:"provider"`
	Model             string      `json:"model"`
	RiskScore         int         `json:"risk_score"`
	Summary           string      `json:"summary"`
	Reasoning         string      `json:"reasoning"`
	RecommendedAction Action      `json:"recommended_action"`
	SuggestedRule     string      `json:"suggested_rule,omitempty"`
	DowngradeBlocked  bool        `json:"downgrade_blocked,omitempty"`
	Disagreement      bool        `json:"disagreement,omitempty"`
	RefusalCount      int         `json:"refusal_count,omitempty"`
	Votes             []ModelVote `json:"votes,omitempty"`
	LatencyMS         int64       `json:"latency_ms"`
	FallbackUsed      bool        `json:"fallback_used,omitempty"`
	Error             string      `json:"error,omitempty"`
	PromptFlags       []string    `json:"prompt_flags,omitempty"`
}

type IncidentStatus string

const (
	StatusOpen    IncidentStatus = "open"
	StatusFrozen  IncidentStatus = "frozen"
	StatusKilled  IncidentStatus = "killed"
	StatusResumed IncidentStatus = "resumed"
	StatusAllowed IncidentStatus = "allowed"
	StatusBlocked IncidentStatus = "blocked"
)

type Incident struct {
	ID                  string         `json:"id"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	Event               Event          `json:"event"`
	Matches             []PolicyMatch  `json:"matches"`
	DeterministicAction Action         `json:"deterministic_action"`
	EffectiveAction     Action         `json:"effective_action"`
	Severity            Severity       `json:"severity"`
	Status              IncidentStatus `json:"status"`
	EnforcementNote     string         `json:"enforcement_note,omitempty"`
	AI                  *AIAnalysis    `json:"ai,omitempty"`
}

type DaemonStatus struct {
	Version        string    `json:"version"`
	Mode           string    `json:"mode"`
	SensorMode     string    `json:"sensor_mode"`
	StartedAt      time.Time `json:"started_at"`
	PolicyCount    int       `json:"policy_count"`
	EventsTotal    uint64    `json:"events_total"`
	IncidentsTotal uint64    `json:"incidents_total"`
	FrozenCount    int       `json:"frozen_count"`
	AIEnabled      bool      `json:"ai_enabled"`
	AIStrategy     string    `json:"ai_strategy"`
	AIModels       []string  `json:"ai_models"`
	AuditLogPath   string    `json:"audit_log_path"`
}
