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

// IndiaSource searches India-specific public records using Wikipedia,
// Yahoo Finance (NSE/BSE), and Indian social/professional platforms.
type IndiaSource struct{}

func (s *IndiaSource) Name() string { return "india" }

func (s *IndiaSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *IndiaSource) IsAvailable(_ config.Config) bool { return true }

// Indian platforms with correct, working username URL patterns.
var indianPlatforms = []Platform{
	// Competitive programming (Indian-origin)
	{Name: "CodeChef", URLTemplate: "https://www.codechef.com/users/{}",
		NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "HackerEarth", URLTemplate: "https://www.hackerearth.com/@{}",
		NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "InterviewBit", URLTemplate: "https://www.interviewbit.com/profile/{}",
		NotFoundStatus: 404, Severity: result.SeverityMedium},
	// Commerce / professional
	{Name: "IndiaMART", URLTemplate: "https://www.indiamart.com/{}/",
		NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Instamojo", URLTemplate: "https://www.instamojo.com/{}/",
		NotFoundStatus: 404, Severity: result.SeverityMedium},
}

// ─── Search ───────────────────────────────────────────────────────────────────

func (s *IndiaSource) Search(
	ctx context.Context,
	q query.Query,
	clients HTTPClients,
	cfg config.Config,
	out chan<- result.Finding,
) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	// Wikipedia India search runs for ALL query types — always returns data.
	wikiFindings, err := wikiIndiaSearch(ctx, clients.Clear, q.Raw, q.Type)
	if err == nil {
		for _, f := range wikiFindings {
			out <- f
			meta.Count++
		}
	}

	switch q.Type {

	case query.TargetUsername:
		for _, p := range indianPlatforms {
			select {
			case <-ctx.Done():
				return meta, ctx.Err()
			default:
			}
			found, profileURL, _ := checkPlatform(ctx, clients.Clear, p, q.Raw)
			if !found {
				continue
			}
			out <- result.Finding{
				ID:       uuid.New().String(),
				Source:   "india",
				Variant:  q.Raw,
				Type:     "social",
				Title:    fmt.Sprintf("%s: %s", p.Name, q.Raw),
				Summary:  fmt.Sprintf("Account found on Indian platform: %s", p.Name),
				URL:      profileURL,
				Severity: p.Severity,
				FoundAt:  time.Now(),
				Raw: map[string]any{
					"platform": p.Name,
					"username": q.Raw,
					"url":      profileURL,
					"region":   "india",
				},
			}
			meta.Count++
		}

	case query.TargetCompany:
		// Yahoo Finance India — NSE/BSE listing
		if findings, err := yahooFinanceIndia(ctx, clients.Clear, q.Raw); err == nil {
			for _, f := range findings {
				out <- f
				meta.Count++
			}
		}

		// Screener.in company search (Indian stock screener, public JSON API)
		if findings, err := screenerSearch(ctx, clients.Clear, q.Raw); err == nil {
			for _, f := range findings {
				out <- f
				meta.Count++
			}
		}

	case query.TargetPerson:
		// Person-specific Wikipedia searches
		if findings, err := wikiPersonIndia(ctx, clients.Clear, q.Raw); err == nil {
			for _, f := range findings {
				out <- f
				meta.Count++
			}
		}
	}

	return meta, nil
}

// ─── Wikipedia India Search ───────────────────────────────────────────────────

// wikiIndiaSearch searches Wikipedia for India-related articles about the target.
func wikiIndiaSearch(ctx context.Context, client *http.Client, rawQuery string, targetType query.TargetType) ([]result.Finding, error) {
	// Append "india" to narrow results to Indian context
	searchTerm := rawQuery + " india"

	endpoint := "https://en.wikipedia.org/w/api.php?" + url.Values{
		"action":   {"query"},
		"list":     {"search"},
		"srsearch": {searchTerm},
		"format":   {"json"},
		"srlimit":  {"5"},
		"srprop":   {"snippet|titlesnippet|size"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sandman-osint/1.0 (OSINT research tool)")
	req.Header.Set("Accept", "application/json")

	c := &http.Client{Timeout: 12 * time.Second, Transport: client.Transport}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wikipedia: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var wikiResp struct {
		Query struct {
			SearchInfo struct {
				TotalHits int `json:"totalhits"`
			} `json:"searchinfo"`
			Search []struct {
				Title   string `json:"title"`
				PageID  int    `json:"pageid"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &wikiResp); err != nil {
		return nil, err
	}

	var findings []result.Finding
	for _, item := range wikiResp.Query.Search {
		// Skip articles that don't seem India-related by title/snippet
		combined := strings.ToLower(item.Title + " " + item.Snippet)
		if !strings.Contains(combined, "india") &&
			!strings.Contains(combined, "indian") &&
			!strings.Contains(combined, "mumbai") &&
			!strings.Contains(combined, "delhi") &&
			!strings.Contains(combined, "bengaluru") &&
			!strings.Contains(combined, "bangalore") &&
			!strings.Contains(combined, "chennai") &&
			!strings.Contains(combined, "hyderabad") {
			continue
		}

		// Strip HTML tags from snippet
		snippet := stripWikiTags(item.Snippet)

		wikiURL := fmt.Sprintf("https://en.wikipedia.org/wiki/%s",
			url.PathEscape(strings.ReplaceAll(item.Title, " ", "_")))

		sev := result.SeverityMedium
		if targetType == query.TargetPerson {
			sev = result.SeverityHigh
		}

		findings = append(findings, result.Finding{
			ID:      uuid.New().String(),
			Source:  "india",
			Variant: rawQuery,
			Type:    "profile",
			Title:   fmt.Sprintf("[Wikipedia] %s", item.Title),
			Summary: snippet,
			URL:     wikiURL,
			Severity: sev,
			FoundAt: time.Now(),
			Raw: map[string]any{
				"page_id": item.PageID,
				"title":   item.Title,
				"source":  "wikipedia",
				"region":  "india",
			},
		})
	}
	return findings, nil
}

// wikiPersonIndia gets a Wikipedia extract specifically for a person in India context.
func wikiPersonIndia(ctx context.Context, client *http.Client, personName string) ([]result.Finding, error) {
	// Search for the person directly by name first
	endpoint := "https://en.wikipedia.org/w/api.php?" + url.Values{
		"action":  {"query"},
		"list":    {"search"},
		"srsearch": {personName},
		"format":  {"json"},
		"srlimit": {"3"},
		"srprop":  {"snippet|titlesnippet"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sandman-osint/1.0")
	req.Header.Set("Accept", "application/json")

	c := &http.Client{Timeout: 12 * time.Second, Transport: client.Transport}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil, err
	}

	var wikiResp struct {
		Query struct {
			Search []struct {
				Title   string `json:"title"`
				PageID  int    `json:"pageid"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &wikiResp); err != nil {
		return nil, err
	}

	var findings []result.Finding
	for _, item := range wikiResp.Query.Search {
		snippet := stripWikiTags(item.Snippet)
		if snippet == "" {
			continue
		}
		// Only include results that name-match (avoid unrelated articles)
		nameParts := strings.Fields(strings.ToLower(personName))
		titleLower := strings.ToLower(item.Title)
		matched := false
		for _, part := range nameParts {
			if len(part) > 2 && strings.Contains(titleLower, part) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		wikiURL := fmt.Sprintf("https://en.wikipedia.org/wiki/%s",
			url.PathEscape(strings.ReplaceAll(item.Title, " ", "_")))

		findings = append(findings, result.Finding{
			ID:       uuid.New().String(),
			Source:   "india",
			Variant:  personName,
			Type:     "profile",
			Title:    fmt.Sprintf("[Wikipedia] %s", item.Title),
			Summary:  snippet,
			URL:      wikiURL,
			Severity: result.SeverityHigh,
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"page_id": item.PageID,
				"title":   item.Title,
				"source":  "wikipedia",
				"region":  "india",
			},
		})
	}
	return findings, nil
}

// stripWikiTags removes HTML span tags added by Wikipedia search highlight.
func stripWikiTags(s string) string {
	// Remove <span class="searchmatch">...</span> and other tags
	result := strings.Builder{}
	inTag := false
	for _, ch := range s {
		if ch == '<' {
			inTag = true
			continue
		}
		if ch == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(ch)
		}
	}
	// Decode basic HTML entities
	out := result.String()
	out = strings.ReplaceAll(out, "&amp;", "&")
	out = strings.ReplaceAll(out, "&lt;", "<")
	out = strings.ReplaceAll(out, "&gt;", ">")
	out = strings.ReplaceAll(out, "&quot;", `"`)
	out = strings.ReplaceAll(out, "&#39;", "'")
	return strings.TrimSpace(out)
}

// ─── Yahoo Finance India ──────────────────────────────────────────────────────

func yahooFinanceIndia(ctx context.Context, client *http.Client, company string) ([]result.Finding, error) {
	endpoint := "https://query1.finance.yahoo.com/v1/finance/search?" +
		"q=" + url.QueryEscape(company) +
		"&lang=en-US&region=IN&quotesCount=5&newsCount=0" +
		"&enableFuzzyQuery=false&enableCb=false&enableNavLinks=false"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "application/json, */*")

	c := &http.Client{Timeout: 12 * time.Second, Transport: client.Transport}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("yahoo finance: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var yf struct {
		Finance struct {
			Result []struct {
				Quotes []struct {
					Symbol    string  `json:"symbol"`
					LongName  string  `json:"longname"`
					ShortName string  `json:"shortname"`
					Exchange  string  `json:"exchange"`
					QuoteType string  `json:"quoteType"`
					Score     float64 `json:"score"`
				} `json:"quotes"`
			} `json:"result"`
		} `json:"finance"`
	}
	if err := json.Unmarshal(body, &yf); err != nil {
		return nil, err
	}

	var findings []result.Finding
	seen := map[string]bool{}
	for _, r := range yf.Finance.Result {
		for _, q := range r.Quotes {
			if !strings.HasSuffix(q.Symbol, ".NS") && !strings.HasSuffix(q.Symbol, ".BO") {
				continue
			}
			if seen[q.Symbol] {
				continue
			}
			seen[q.Symbol] = true

			name := q.LongName
			if name == "" {
				name = q.ShortName
			}
			exchange := "NSE"
			if strings.HasSuffix(q.Symbol, ".BO") {
				exchange = "BSE"
			}
			sym := strings.TrimSuffix(strings.TrimSuffix(q.Symbol, ".NS"), ".BO")

			listingURL := "https://www.nseindia.com/get-quotes/equity?symbol=" + url.QueryEscape(sym)
			if exchange == "BSE" {
				listingURL = "https://www.bseindia.com/stock-share-price/" + url.QueryEscape(strings.ToLower(sym))
			}

			findings = append(findings, result.Finding{
				ID:      uuid.New().String(),
				Source:  "india",
				Variant: company,
				Type:    "profile",
				Title:   fmt.Sprintf("[%s] %s (%s)", exchange, name, sym),
				Summary: fmt.Sprintf("%s is publicly listed on %s India under symbol %s (type: %s).",
					name, exchange, sym, q.QuoteType),
				URL:      listingURL,
				Severity: result.SeverityHigh,
				FoundAt:  time.Now(),
				Raw: map[string]any{
					"symbol":   q.Symbol,
					"name":     name,
					"exchange": exchange,
					"type":     q.QuoteType,
					"region":   "india",
				},
			})
		}
	}
	return findings, nil
}

// ─── Screener.in ─────────────────────────────────────────────────────────────

// screenerSearch queries screener.in for Indian listed company data (public, no auth).
func screenerSearch(ctx context.Context, client *http.Client, company string) ([]result.Finding, error) {
	endpoint := "https://www.screener.in/api/company/search/?q=" + url.QueryEscape(company) + "&v=3&fts=1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://www.screener.in/")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	c := &http.Client{Timeout: 10 * time.Second, Transport: client.Transport}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("screener: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil, err
	}

	// Screener returns [{name, url, ...}, ...]
	var results []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	var findings []result.Finding
	for _, r := range results {
		if r.Name == "" {
			continue
		}
		fullURL := "https://www.screener.in" + r.URL
		findings = append(findings, result.Finding{
			ID:      uuid.New().String(),
			Source:  "india",
			Variant: company,
			Type:    "profile",
			Title:   fmt.Sprintf("[Screener] %s", r.Name),
			Summary: fmt.Sprintf("Indian listed company found on Screener.in — financial data, shareholding, and annual reports available."),
			URL:     fullURL,
			Severity: result.SeverityHigh,
			FoundAt: time.Now(),
			Raw: map[string]any{
				"name":   r.Name,
				"source": "screener.in",
				"region": "india",
			},
		})
	}
	return findings, nil
}
