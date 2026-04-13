package engine

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"sandman-osint/internal/ai"
	"sandman-osint/internal/config"
	"sandman-osint/internal/permutation"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
	"sandman-osint/internal/sources"
	"sandman-osint/internal/sse"
)

const searchTimeout = 6 * time.Minute

// Engine orchestrates concurrent searches across all registered sources.
type Engine struct {
	cfg      config.Config
	clients  sources.HTTPClients
	broker   *sse.Broker
	store    *Store
	analyzer *ai.Analyzer
}

// New creates an Engine wired to the given dependencies.
func New(cfg config.Config, clients sources.HTTPClients, broker *sse.Broker, store *Store, analyzer *ai.Analyzer) *Engine {
	return &Engine{
		cfg:      cfg,
		clients:  clients,
		broker:   broker,
		store:    store,
		analyzer: analyzer,
	}
}

// Submit generates permutations, stores the query, and starts the search async.
// Returns the query ID immediately.
func (e *Engine) Submit(raw string, targetType query.TargetType, useTor bool) string {
	q := query.Query{
		ID:        uuid.New().String(),
		Raw:       raw,
		Type:      targetType,
		Variants:  permutation.Generate(raw, targetType),
		UseTor:    useTor,
		CreatedAt: time.Now(),
	}
	e.store.Create(q)
	go e.run(q)
	return q.ID
}

// run executes the full search lifecycle. Called in a goroutine by Submit.
func (e *Engine) run(q query.Query) {
	ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
	defer cancel()

	// Determine which sources will run
	var active []sources.Source
	for _, src := range sources.Registry {
		if !supportsType(src, q.Type) {
			e.skipSource(q.ID, src.Name())
			continue
		}
		if src.Name() == "tor" && e.clients.Tor == nil {
			e.skipSource(q.ID, src.Name())
			continue
		}
		if !src.IsAvailable(e.cfg) {
			e.skipSource(q.ID, src.Name())
			continue
		}
		active = append(active, src)
	}

	slog.Info("search started",
		"id", q.ID,
		"target", q.Raw,
		"type", q.Type,
		"variants", len(q.Variants),
		"active_sources", len(active),
	)

	// Announce total source count so the UI can show X/N progress
	e.broker.Publish(q.ID, sse.Event{Name: "search_meta", Data: map[string]any{
		"total_sources": len(active) + countSkipped(sources.Registry, active),
		"variants":      len(q.Variants),
	}})

	dedup := newDeduper()
	findingsCh := make(chan result.Finding, 512)

	var wg sync.WaitGroup
	for _, src := range active {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			e.runSource(ctx, s, q, findingsCh)
		}(src)
	}

	// Collector: relay deduplicated findings to broker + store
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for f := range findingsCh {
			if !dedup.add(f) {
				continue // duplicate — drop
			}
			e.store.AddFinding(q.ID, f)
			e.broker.Publish(q.ID, sse.Event{Name: "finding", Data: f})
		}
	}()

	wg.Wait()
	close(findingsCh)
	<-collectorDone

	// AI analysis
	if e.analyzer != nil {
		res, _ := e.store.Get(q.ID)
		if res != nil && len(res.Findings) > 0 {
			analysis, err := e.analyzer.Analyze(ctx, q, res.Findings)
			if err != nil {
				slog.Warn("AI analysis failed", "err", err)
			} else if analysis != nil {
				e.store.SetAIAnalysis(q.ID, analysis)
				e.broker.Publish(q.ID, sse.Event{Name: "ai_analysis", Data: analysis})
			}
		}
	}

	e.store.SetStatus(q.ID, query.StatusDone)
	e.broker.Publish(q.ID, sse.Event{Name: "done", Data: map[string]any{
		"query_id":       q.ID,
		"total_findings": e.store.Count(q.ID),
	}})

	slog.Info("search complete", "id", q.ID, "findings", e.store.Count(q.ID))
}

func (e *Engine) runSource(ctx context.Context, src sources.Source, q query.Query, out chan<- result.Finding) {
	meta := result.SourceMeta{Name: src.Name(), Status: "running"}
	e.store.UpsertSource(q.ID, meta)
	e.broker.Publish(q.ID, sse.Event{Name: "source_update", Data: meta})

	start := time.Now()
	finalMeta, err := src.Search(ctx, q, e.clients, e.cfg, out)
	finalMeta.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		if err == context.DeadlineExceeded {
			finalMeta.Status = "timeout"
		} else {
			finalMeta.Status = "error"
			finalMeta.Error = err.Error()
		}
		slog.Warn("source finished with error", "source", src.Name(), "err", err)
	} else {
		finalMeta.Status = "done"
	}

	e.store.UpsertSource(q.ID, finalMeta)
	e.broker.Publish(q.ID, sse.Event{Name: "source_update", Data: finalMeta})
}

func (e *Engine) skipSource(queryID, name string) {
	meta := result.SourceMeta{Name: name, Status: "skipped"}
	e.store.UpsertSource(queryID, meta)
	e.broker.Publish(queryID, sse.Event{Name: "source_update", Data: meta})
}

// ─── Deduplication ───────────────────────────────────────────────────────────

type deduper struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newDeduper() *deduper {
	return &deduper{seen: make(map[string]bool)}
}

// add returns true if the finding is new, false if it was already seen.
func (d *deduper) add(f result.Finding) bool {
	key := f.Source + "|" + f.Type + "|"
	if f.URL != "" {
		key += strings.ToLower(f.URL)
	} else {
		key += strings.ToLower(f.Title)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen[key] {
		return false
	}
	d.seen[key] = true
	return true
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func supportsType(src sources.Source, t query.TargetType) bool {
	for _, supported := range src.TargetTypes() {
		if supported == t {
			return true
		}
	}
	return false
}

func countSkipped(all []sources.Source, active []sources.Source) int {
	activeSet := make(map[string]bool, len(active))
	for _, s := range active {
		activeSet[s.Name()] = true
	}
	count := 0
	for _, s := range all {
		if !activeSet[s.Name()] {
			count++
		}
	}
	return count
}
