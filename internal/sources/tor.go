package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// TorSource searches .onion services for OSINT intelligence.
// It is automatically skipped when Tor is unavailable.
type TorSource struct{}

func (s *TorSource) Name() string { return "tor" }

func (s *TorSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

// IsAvailable always returns true; the engine skips this source when clients.Tor is nil.
func (s *TorSource) IsAvailable(_ config.Config) bool { return true }

// onionSearchEngines lists .onion search/paste sites to query.
var onionSearchEngines = []struct {
	Name     string
	URLFmt   string
	ResultRe string
}{
	{
		Name:     "Ahmia",
		URLFmt:   "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=%s",
		ResultRe: `<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>`,
	},
}

var reTorLink = regexp.MustCompile(`<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>`)

func (s *TorSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	if clients.Tor == nil {
		meta.Status = "skipped"
		return meta, nil
	}

	terms := []string{q.Raw}
	// Add top username variant
	for _, v := range q.Variants {
		if !IsEmail(v) && !IsDomain(v) && !strings.ContainsRune(v, ' ') {
			terms = append(terms, v)
			break
		}
	}

	for _, eng := range onionSearchEngines {
		for _, term := range terms[:min(len(terms), 2)] {
			select {
			case <-ctx.Done():
				return meta, ctx.Err()
			default:
			}

			findings, err := s.searchOnion(ctx, clients.Tor, eng.Name, fmt.Sprintf(eng.URLFmt, url.QueryEscape(term)), term)
			if err != nil {
				continue
			}
			for _, f := range findings {
				out <- f
				meta.Count++
			}
			time.Sleep(3 * time.Second) // Tor is slow; be patient
		}
	}

	return meta, nil
}

func (s *TorSource) searchOnion(ctx context.Context, client *http.Client, engineName, searchURL, term string) ([]result.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("onion search returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}

	matches := reTorLink.FindAllStringSubmatch(string(body), 20)
	var findings []result.Finding

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		link := m[1]
		title := stripTags(m[2])

		if link == "" || title == "" || len(title) < 5 {
			continue
		}
		// Skip search engine internal links
		if strings.Contains(link, "ahmia") || strings.Contains(link, "duckduckgo") {
			continue
		}

		isOnion := strings.Contains(link, ".onion")
		sev := result.SeverityMedium
		if isOnion {
			sev = result.SeverityHigh
		}

		findings = append(findings, result.Finding{
			ID:       uuid.New().String(),
			Source:   "tor",
			Variant:  term,
			Type:     "darkweb",
			Title:    title,
			Summary:  fmt.Sprintf("Found via %s (Tor) — %s", engineName, link),
			URL:      link,
			Severity: sev,
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"engine": engineName,
				"term":   term,
				"link":   link,
				"onion":  isOnion,
			},
		})
	}

	return findings, nil
}
