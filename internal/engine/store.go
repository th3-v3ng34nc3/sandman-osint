package engine

import (
	"sync"
	"time"

	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// Store is an in-memory repository for search results.
// All methods are safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	results map[string]*result.Result
}

// NewStore creates an empty store.
func NewStore() *Store {
	return &Store{results: make(map[string]*result.Result)}
}

// Create initialises a new result entry for a query.
func (s *Store) Create(q query.Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[q.ID] = &result.Result{
		QueryID:   q.ID,
		Query:     q,
		Findings:  []result.Finding{},
		Sources:   []result.SourceMeta{},
		Status:    query.StatusRunning,
		StartedAt: time.Now(),
	}
}

// AddFinding appends a finding to the result for queryID.
func (s *Store) AddFinding(queryID string, f result.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.results[queryID]; ok {
		r.Findings = append(r.Findings, f)
	}
}

// UpsertSource inserts or replaces a SourceMeta entry.
func (s *Store) UpsertSource(queryID string, sm result.SourceMeta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[queryID]
	if !ok {
		return
	}
	for i, src := range r.Sources {
		if src.Name == sm.Name {
			r.Sources[i] = sm
			return
		}
	}
	r.Sources = append(r.Sources, sm)
}

// SetAIAnalysis stores the AI analysis result.
func (s *Store) SetAIAnalysis(queryID string, a *result.AIAnalysis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.results[queryID]; ok {
		r.AIAnalysis = a
	}
}

// SetStatus updates the lifecycle status of a search.
func (s *Store) SetStatus(queryID string, status query.SearchStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[queryID]
	if !ok {
		return
	}
	r.Status = status
	if status == query.StatusDone || status == query.StatusError {
		t := time.Now()
		r.FinishedAt = &t
	}
}

// Count returns the number of findings for a query.
func (s *Store) Count(queryID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.results[queryID]; ok {
		return len(r.Findings)
	}
	return 0
}

// Get returns a deep copy of the result for queryID.
func (s *Store) Get(queryID string) (*result.Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[queryID]
	if !ok {
		return nil, false
	}
	cp := *r
	cp.Findings = append([]result.Finding{}, r.Findings...)
	cp.Sources = append([]result.SourceMeta{}, r.Sources...)
	return &cp, true
}
