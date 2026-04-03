package engine

import (
	"context"
	"log/slog"
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

// Submit validates the request, generates permutations, persists the query,
// and launches the search asynchronously. It returns the query ID immediately.
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
	go e.run(context.Background(), q)
	return q.ID
}

// run executes the search fan-out. It is called in a goroutine by Submit.
func (e *Engine) run(ctx context.Context, q query.Query) {
	slog.Info("search started", "id", q.ID, "target", q.Raw, "type", q.Type, "variants", len(q.Variants))

	findingsCh := make(chan result.Finding, 512)

	// Fan out to all sources concurrently.
	var wg sync.WaitGroup
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

		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			e.runSource(ctx, s, q, findingsCh)
		}(src)
	}

	// Collector: relay findings to broker and store while sources are running.
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for f := range findingsCh {
			e.store.AddFinding(q.ID, f)
			e.broker.Publish(q.ID, sse.Event{Name: "finding", Data: f})
		}
	}()

	// Wait for all sources to finish, then close the findings channel.
	wg.Wait()
	close(findingsCh)
	<-collectorDone // drain remaining findings

	// Run AI analysis if configured.
	if e.analyzer != nil && e.cfg.ClaudeKey != "" {
		res, _ := e.store.Get(q.ID)
		if res != nil {
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

// runSource executes a single source and publishes status updates.
func (e *Engine) runSource(ctx context.Context, src sources.Source, q query.Query, out chan<- result.Finding) {
	meta := result.SourceMeta{Name: src.Name(), Status: "running"}
	e.store.UpsertSource(q.ID, meta)
	e.broker.Publish(q.ID, sse.Event{Name: "source_update", Data: meta})

	start := time.Now()
	finalMeta, err := src.Search(ctx, q, e.clients, e.cfg, out)
	finalMeta.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		slog.Warn("source error", "source", src.Name(), "err", err)
		finalMeta.Status = "error"
		finalMeta.Error = err.Error()
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

func supportsType(src sources.Source, t query.TargetType) bool {
	for _, supported := range src.TargetTypes() {
		if supported == t {
			return true
		}
	}
	return false
}
