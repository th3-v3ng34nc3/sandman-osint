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

// DuckDuckGoSource scrapes DuckDuckGo HTML search results.
type DuckDuckGoSource struct{}

func (s *DuckDuckGoSource) Name() string { return "duckduckgo" }

func (s *DuckDuckGoSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *DuckDuckGoSource) IsAvailable(_ config.Config) bool { return true }

// searchQuery builds the DDG query string based on target type.
func buildSearchQuery(q query.Query) []string {
	raw := q.Raw
	switch q.Type {
	case query.TargetPerson:
		return []string{
			`"` + raw + `"`,
			`"` + raw + `" site:linkedin.com`,
			`"` + raw + `" email OR contact`,
			`"` + raw + `" github OR twitter OR instagram`,
		}
	case query.TargetUsername:
		return []string{
			raw + " profile",
			`"` + raw + `" site:twitter.com OR site:github.com OR site:reddit.com`,
			`"` + raw + `" username`,
		}
	case query.TargetCompany:
		return []string{
			`"` + raw + `"`,
			`"` + raw + `" employees OR team OR founders`,
			`"` + raw + `" breach OR hack OR leak`,
		}
	}
	return []string{raw}
}

var (
	// Match DDG result titles and URLs from HTML response
	reTitleURL = regexp.MustCompile(`<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	reSnippet  = regexp.MustCompile(`<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>`)
	reTag      = regexp.MustCompile(`<[^>]+>`)
)

func (s *DuckDuckGoSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}
	queries := buildSearchQuery(q)

	for i, searchQ := range queries {
		if i >= 3 {
			break
		}
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		results, err := s.scrape(ctx, clients.Clear, searchQ)
		if err != nil {
			continue
		}

		for _, r := range results {
			out <- r
			meta.Count++
		}
		time.Sleep(2 * time.Second) // be polite to DDG
	}

	return meta, nil
}

func (s *DuckDuckGoSource) scrape(ctx context.Context, client *http.Client, searchQuery string) ([]result.Finding, error) {
	endpoint := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(searchQuery))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)
	titleURLMatches := reTitleURL.FindAllStringSubmatch(html, 10)
	snippetMatches := reSnippet.FindAllStringSubmatch(html, 10)

	var findings []result.Finding
	for i, m := range titleURLMatches {
		if len(m) < 3 {
			continue
		}
		rawURL := m[1]
		title := stripTags(m[2])

		if rawURL == "" || title == "" {
			continue
		}
		// DDG wraps URLs — skip internal DDG links
		if strings.Contains(rawURL, "duckduckgo.com") {
			continue
		}

		summary := ""
		if i < len(snippetMatches) && len(snippetMatches[i]) >= 2 {
			summary = stripTags(snippetMatches[i][1])
		}

		sev := classifyURL(rawURL)

		findings = append(findings, result.Finding{
			ID:       uuid.New().String(),
			Source:   "duckduckgo",
			Variant:  searchQuery,
			Type:     "search",
			Title:    title,
			Summary:  summary,
			URL:      rawURL,
			Severity: sev,
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"query": searchQuery,
				"url":   rawURL,
				"title": title,
			},
		})
	}
	return findings, nil
}

// classifyURL assigns severity based on the domain.
func classifyURL(rawURL string) result.Severity {
	high := []string{"linkedin.com", "facebook.com", "twitter.com", "instagram.com", "pastebin.com"}
	critical := []string{"haveibeenpwned.com", "dehashed.com", "intelx.io", "pipl.com"}

	lower := strings.ToLower(rawURL)
	for _, d := range critical {
		if strings.Contains(lower, d) {
			return result.SeverityCritical
		}
	}
	for _, d := range high {
		if strings.Contains(lower, d) {
			return result.SeverityHigh
		}
	}
	return result.SeverityLow
}

func stripTags(s string) string {
	s = reTag.ReplaceAllString(s, "")
	s = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'").Replace(s)
	return strings.TrimSpace(s)
}
