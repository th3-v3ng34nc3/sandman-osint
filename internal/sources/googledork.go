package sources

import (
	"context"
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

// GoogleDorkSource runs targeted operator-based dork queries through DuckDuckGo HTML.
type GoogleDorkSource struct{}

func (s *GoogleDorkSource) Name() string { return "googledork" }

func (s *GoogleDorkSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *GoogleDorkSource) IsAvailable(_ config.Config) bool { return true }

// dorkQueries returns targeted operator queries for the given target.
func dorkQueries(q query.Query) []string {
	raw := q.Raw
	switch q.Type {
	case query.TargetPerson:
		return []string{
			fmt.Sprintf(`"%s" filetype:pdf`, raw),
			fmt.Sprintf(`"%s" site:pastebin.com`, raw),
			fmt.Sprintf(`"%s" email OR phone OR address`, raw),
			fmt.Sprintf(`"%s" inurl:profile`, raw),
			fmt.Sprintf(`"%s" resume OR "curriculum vitae"`, raw),
			fmt.Sprintf(`"%s" site:academia.edu OR site:researchgate.net`, raw),
			fmt.Sprintf(`"%s" site:crunchbase.com OR site:about.me`, raw),
		}
	case query.TargetUsername:
		return []string{
			fmt.Sprintf(`inurl:"%s"`, raw),
			fmt.Sprintf(`"%s" site:pastebin.com`, raw),
			fmt.Sprintf(`"%s" site:github.com OR site:gitlab.com`, raw),
			fmt.Sprintf(`"@%s"`, raw),
			fmt.Sprintf(`"%s" dump OR leak OR breach`, raw),
			fmt.Sprintf(`intitle:"%s" profile`, raw),
		}
	case query.TargetCompany:
		return []string{
			fmt.Sprintf(`"%s" employees site:linkedin.com`, raw),
			fmt.Sprintf(`"%s" "data breach" OR "data leak" OR "exposed"`, raw),
			fmt.Sprintf(`"%s" filetype:pdf "annual report" OR "financial report"`, raw),
			fmt.Sprintf(`"%s" site:crunchbase.com OR site:pitchbook.com`, raw),
			fmt.Sprintf(`"%s" vulnerability CVE exploit`, raw),
			fmt.Sprintf(`"%s" "internal document" OR confidential`, raw),
		}
	}
	return []string{fmt.Sprintf(`"%s"`, raw)}
}

func (s *GoogleDorkSource) Search(
	ctx context.Context,
	q query.Query,
	clients HTTPClients,
	cfg config.Config,
	out chan<- result.Finding,
) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}
	dorks := dorkQueries(q)

	maxDorks := 4
	if len(dorks) < maxDorks {
		maxDorks = len(dorks)
	}

	for i := 0; i < maxDorks; i++ {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		findings, err := dorkScrape(ctx, clients.Clear, dorks[i])
		if err != nil {
			continue
		}

		for _, f := range findings {
			out <- f
			meta.Count++
		}

		if i < maxDorks-1 {
			select {
			case <-ctx.Done():
				return meta, ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}

	return meta, nil
}

// dorkScrape performs a DuckDuckGo HTML search and returns parsed findings.
func dorkScrape(ctx context.Context, client *http.Client, dork string) ([]result.Finding, error) {
	endpoint := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(dork)

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}

	html := string(body)
	titleURLMatches := reTitleURL.FindAllStringSubmatch(html, 8)
	snippetMatches := reSnippet.FindAllStringSubmatch(html, 8)

	var findings []result.Finding
	for i, m := range titleURLMatches {
		if len(m) < 3 {
			continue
		}
		rawURL := m[1]
		title := stripTags(m[2])

		if rawURL == "" || title == "" || strings.Contains(rawURL, "duckduckgo.com") {
			continue
		}

		summary := ""
		if i < len(snippetMatches) && len(snippetMatches[i]) >= 2 {
			summary = stripTags(snippetMatches[i][1])
		}

		findings = append(findings, result.Finding{
			ID:       uuid.New().String(),
			Source:   "googledork",
			Variant:  dork,
			Type:     "search",
			Title:    title,
			Summary:  summary,
			URL:      rawURL,
			Severity: classifyDorkURL(rawURL),
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"dork":  dork,
				"url":   rawURL,
				"title": title,
			},
		})
	}

	return findings, nil
}

// classifyDorkURL assigns severity based on domain significance for dork results.
func classifyDorkURL(rawURL string) result.Severity {
	lower := strings.ToLower(rawURL)

	criticals := []string{
		"pastebin.com", "dehashed.com", "haveibeenpwned.com",
		"intelx.io", "raidforums.com", "breachforums.com", "ghostbin.com",
	}
	highs := []string{
		"linkedin.com", "facebook.com", "twitter.com", "x.com",
		"instagram.com", "github.com", "gitlab.com",
		"academia.edu", "researchgate.net", "crunchbase.com",
	}

	for _, d := range criticals {
		if strings.Contains(lower, d) {
			return result.SeverityCritical
		}
	}
	for _, d := range highs {
		if strings.Contains(lower, d) {
			return result.SeverityHigh
		}
	}
	if strings.HasSuffix(lower, ".pdf") || strings.Contains(lower, ".pdf?") ||
		strings.HasSuffix(lower, ".doc") || strings.HasSuffix(lower, ".docx") ||
		strings.HasSuffix(lower, ".xls") || strings.HasSuffix(lower, ".xlsx") {
		return result.SeverityMedium
	}
	return result.SeverityLow
}
