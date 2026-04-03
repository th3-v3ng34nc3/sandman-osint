package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"sandman-osint/internal/config"
	"sandman-osint/internal/engine"
	"sandman-osint/internal/query"
	"sandman-osint/internal/sse"
)

//go:embed static
var embedStatic embed.FS

// Server wires HTTP handlers to the engine, broker, and store.
type Server struct {
	cfg    config.Config
	eng    *engine.Engine
	broker *sse.Broker
	store  *engine.Store
}

// NewServer creates a new Server.
func NewServer(cfg config.Config, eng *engine.Engine, broker *sse.Broker, store *engine.Store) *Server {
	return &Server{cfg: cfg, eng: eng, broker: broker, store: store}
}

// RegisterRoutes registers all HTTP routes on the given mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// API routes (registered before the static catch-all)
	mux.HandleFunc("POST /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/export", s.handleExport)

	// Static file server (catch-all)
	staticFS, err := fs.Sub(embedStatic, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

type searchRequest struct {
	Raw    string `json:"raw"`
	Type   string `json:"type"`
	UseTor bool   `json:"use_tor"`
}

type searchResponse struct {
	QueryID string `json:"query_id"`
}

// POST /api/search — submit a new search, returns query_id immediately.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req searchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Raw = strings.TrimSpace(req.Raw)
	if req.Raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw target is required"})
		return
	}

	t := query.TargetType(req.Type)
	switch t {
	case query.TargetPerson, query.TargetUsername, query.TargetCompany:
	default:
		t = query.TargetPerson
	}

	id := s.eng.Submit(req.Raw, t, req.UseTor)
	slog.Info("search submitted", "id", id, "target", req.Raw, "type", t)

	writeJSON(w, http.StatusAccepted, searchResponse{QueryID: id})
}

// GET /api/stream?id=<queryID> — SSE stream of search events.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	queryID := r.URL.Query().Get("id")
	if queryID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	// Verify the query exists
	if _, ok := s.store.Get(queryID); !ok {
		http.Error(w, "query not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// If query is already done, stream its cached results immediately.
	res, _ := s.store.Get(queryID)
	if res != nil && (res.Status == query.StatusDone || res.Status == query.StatusError) {
		for _, sm := range res.Sources {
			writeSSE(w, flusher, "source_update", sm)
		}
		for _, f := range res.Findings {
			writeSSE(w, flusher, "finding", f)
		}
		if res.AIAnalysis != nil {
			writeSSE(w, flusher, "ai_analysis", res.AIAnalysis)
		}
		writeSSE(w, flusher, "done", map[string]any{
			"query_id":       queryID,
			"total_findings": len(res.Findings),
		})
		return
	}

	ch, unsubscribe := s.broker.Subscribe(queryID)
	defer unsubscribe()

	// Send a heartbeat comment every 15s to keep the connection alive.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, flusher, event.Name, event.Data)
			if event.Name == "done" || event.Name == "error" {
				return
			}
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// GET /api/status?id=<queryID> — returns current status (for page-reload recovery).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	queryID := r.URL.Query().Get("id")
	if queryID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}

	res, ok := s.store.Get(queryID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "query not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"query_id":       res.QueryID,
		"status":         res.Status,
		"total_findings": len(res.Findings),
		"sources":        res.Sources,
		"started_at":     res.StartedAt,
		"finished_at":    res.FinishedAt,
	})
}

// GET /api/export?id=<queryID> — download the full result as indented JSON.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	queryID := r.URL.Query().Get("id")
	if queryID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}

	res, ok := s.store.Get(queryID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "query not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sandman-%s.json"`, queryID[:8]))

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, eventName string, data any) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, b)
	flusher.Flush()
}
