package result

import (
	"time"

	"sandman-osint/internal/query"
)

// Severity classifies how sensitive or significant a finding is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is a single atomic piece of intelligence from one source.
type Finding struct {
	ID       string         `json:"id"`
	Source   string         `json:"source"`
	Variant  string         `json:"variant"`
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Summary  string         `json:"summary"`
	URL      string         `json:"url,omitempty"`
	Raw      map[string]any `json:"raw,omitempty"`
	Severity Severity       `json:"severity"`
	FoundAt  time.Time      `json:"found_at"`
}

// SourceMeta tracks the state and result count of one source during a run.
type SourceMeta struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // pending | running | done | error | skipped
	Count      int    `json:"count"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// AIAnalysis is the structured output from the Claude analysis pass.
type AIAnalysis struct {
	Summary     string   `json:"summary"`
	RiskScore   int      `json:"risk_score"` // 0–100
	KeyFindings []string `json:"key_findings"`
	Connections []string `json:"connections"`
	RawResponse string   `json:"raw_response"`
}

// Result is the full accumulated result set for one Query.
type Result struct {
	QueryID    string             `json:"query_id"`
	Query      query.Query        `json:"query"`
	Findings   []Finding          `json:"findings"`
	Sources    []SourceMeta       `json:"sources"`
	AIAnalysis *AIAnalysis        `json:"ai_analysis,omitempty"`
	Status     query.SearchStatus `json:"status"`
	StartedAt  time.Time          `json:"started_at"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
}
