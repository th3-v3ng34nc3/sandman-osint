package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// HIBPSource checks email addresses against HaveIBeenPwned v3.
type HIBPSource struct{}

func (s *HIBPSource) Name() string { return "hibp" }

func (s *HIBPSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson}
}

func (s *HIBPSource) IsAvailable(cfg config.Config) bool {
	return cfg.HIBPKey != ""
}

type hibpBreach struct {
	Name        string `json:"Name"`
	Title       string `json:"Title"`
	Domain      string `json:"Domain"`
	BreachDate  string `json:"BreachDate"`
	PwnCount    int    `json:"PwnCount"`
	Description string `json:"Description"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool   `json:"IsVerified"`
	IsSensitive bool   `json:"IsSensitive"`
}

func (s *HIBPSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	// Only check email-shaped variants
	emails := make([]string, 0)
	for _, v := range q.Variants {
		if IsEmail(v) {
			emails = append(emails, v)
		}
	}

	if len(emails) == 0 {
		meta.Status = "skipped"
		return meta, nil
	}

	for _, email := range emails {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		breaches, err := s.checkEmail(ctx, clients.Clear, cfg.HIBPKey, email)
		if err != nil {
			continue // non-fatal, try next email
		}

		for _, b := range breaches {
			severity := result.SeverityMedium
			if b.IsSensitive {
				severity = result.SeverityHigh
			}
			if b.PwnCount > 1_000_000 {
				severity = result.SeverityCritical
			}

			out <- result.Finding{
				ID:      uuid.New().String(),
				Source:  s.Name(),
				Variant: email,
				Type:    "breach",
				Title:   fmt.Sprintf("Breach: %s (%s)", b.Title, b.BreachDate),
				Summary: fmt.Sprintf("%s — %s — %d accounts compromised. Data: %s",
					email, b.Domain, b.PwnCount, strings.Join(b.DataClasses, ", ")),
				URL:      fmt.Sprintf("https://haveibeenpwned.com/account/%s", email),
				Severity: severity,
				FoundAt:  time.Now(),
				Raw: map[string]any{
					"email":        email,
					"breach_name":  b.Name,
					"breach_date":  b.BreachDate,
					"pwn_count":    b.PwnCount,
					"data_classes": b.DataClasses,
					"is_sensitive": b.IsSensitive,
					"domain":       b.Domain,
				},
			}
			meta.Count++
		}

		time.Sleep(1600 * time.Millisecond) // HIBP rate limit: 1 req/1.5s
	}

	return meta, nil
}

func (s *HIBPSource) checkEmail(ctx context.Context, client *http.Client, apiKey, email string) ([]hibpBreach, error) {
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("hibp-api-key", apiKey)
	req.Header.Set("User-Agent", "Sandman-OSINT/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // clean — no breaches
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HIBP returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var breaches []hibpBreach
	if err := json.Unmarshal(body, &breaches); err != nil {
		return nil, err
	}
	return breaches, nil
}
