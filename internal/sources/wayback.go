package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// WaybackSource checks the Wayback Machine CDX API for archived presence.
type WaybackSource struct{}

func (s *WaybackSource) Name() string { return "wayback" }

func (s *WaybackSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *WaybackSource) IsAvailable(_ config.Config) bool { return true }

var waybackPlatforms = []struct {
	Name   string
	URLFmt string
}{
	{"Twitter/X", "https://twitter.com/%s"},
	{"Instagram", "https://www.instagram.com/%s/"},
	{"GitHub", "https://github.com/%s"},
	{"LinkedIn", "https://www.linkedin.com/in/%s"},
	{"Reddit", "https://www.reddit.com/user/%s"},
	{"Medium", "https://medium.com/@%s"},
}

func (s *WaybackSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	var handles []string
	for _, v := range q.Variants {
		if !IsEmail(v) && !IsDomain(v) && !strings.ContainsRune(v, ' ') {
			handles = append(handles, v)
		}
	}
	if len(handles) == 0 {
		handles = []string{strings.ReplaceAll(strings.ToLower(q.Raw), " ", "")}
	}
	checkHandle := handles[0]

	// Check known platform profile URLs
	for _, p := range waybackPlatforms {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		targetURL := fmt.Sprintf(p.URLFmt, url.PathEscape(checkHandle))
		f, err := s.checkURL(ctx, clients.Clear, p.Name, targetURL, checkHandle)
		if err != nil || f == nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		out <- *f
		meta.Count++
		time.Sleep(500 * time.Millisecond)
	}

	// For company targets also check domain snapshots
	if q.Type == query.TargetCompany {
		for _, v := range q.Variants {
			if IsDomain(v) && strings.HasSuffix(v, ".com") {
				select {
				case <-ctx.Done():
					return meta, ctx.Err()
				default:
				}

				f, err := s.checkURL(ctx, clients.Clear, v, "https://"+v, v)
				if err == nil && f != nil {
					out <- *f
					meta.Count++
				}
				time.Sleep(500 * time.Millisecond)
				break
			}
		}
	}

	return meta, nil
}

func (s *WaybackSource) checkURL(ctx context.Context, client *http.Client, platform, targetURL, variant string) (*result.Finding, error) {
	endpoint := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s&output=json&limit=1&fl=timestamp,original&filter=statuscode:200&collapse=urlkey",
		url.QueryEscape(targetURL),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sandman-osint/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	// rows[0] is headers ["timestamp","original"]; rows[1+] are data
	if len(rows) < 2 {
		return nil, nil
	}

	ts := rows[1][0]
	date := ts
	if len(ts) >= 8 {
		date = ts[:4] + "-" + ts[4:6] + "-" + ts[6:8]
	}
	archiveURL := fmt.Sprintf("https://web.archive.org/web/%s/%s", ts, targetURL)

	return &result.Finding{
		ID:       uuid.New().String(),
		Source:   "wayback",
		Variant:  variant,
		Type:     "archive",
		Title:    fmt.Sprintf("Archived: %s — %s", platform, variant),
		Summary:  fmt.Sprintf("First snapshot: %s · %s", date, targetURL),
		URL:      archiveURL,
		Severity: result.SeverityLow,
		FoundAt:  time.Now(),
		Raw: map[string]any{
			"platform":    platform,
			"url":         targetURL,
			"first_seen":  date,
			"archive_url": archiveURL,
		},
	}, nil
}
