package query

import "time"

// TargetType classifies what the search target represents.
type TargetType string

const (
	TargetPerson   TargetType = "person"
	TargetUsername TargetType = "username"
	TargetCompany  TargetType = "company"
)

// SearchStatus represents the lifecycle state of a search.
type SearchStatus string

const (
	StatusPending SearchStatus = "pending"
	StatusRunning SearchStatus = "running"
	StatusDone    SearchStatus = "done"
	StatusError   SearchStatus = "error"
)

// Query is the canonical input handed to every source and the engine.
type Query struct {
	ID        string     `json:"id"`
	Raw       string     `json:"raw"`
	Type      TargetType `json:"type"`
	Variants  []string   `json:"variants"`
	UseTor    bool       `json:"use_tor"`
	CreatedAt time.Time  `json:"created_at"`
}
