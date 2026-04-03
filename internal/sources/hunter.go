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

// HunterSource finds professional email addresses via Hunter.io.
type HunterSource struct{}

func (s *HunterSource) Name() string { return "hunter" }

func (s *HunterSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetCompany}
}

func (s *HunterSource) IsAvailable(cfg config.Config) bool {
	return cfg.HunterKey != ""
}

type hunterDomainResp struct {
	Data struct {
		Domain       string `json:"domain"`
		Organization string `json:"organization"`
		Pattern      string `json:"pattern"`
		Emails       []struct {
			Value      string `json:"value"`
			Type       string `json:"type"`
			Confidence int    `json:"confidence"`
			FirstName  string `json:"first_name"`
			LastName   string `json:"last_name"`
			Position   string `json:"position"`
			LinkedIn   string `json:"linkedin"`
		} `json:"emails"`
	} `json:"data"`
}

type hunterEmailVerifyResp struct {
	Data struct {
		Status     string `json:"status"`
		Score      int    `json:"score"`
		Email      string `json:"email"`
		Regexp     bool   `json:"regexp"`
		Gibberish  bool   `json:"gibberish"`
		Disposable bool   `json:"disposable"`
		Webmail    bool   `json:"webmail"`
		MXRecords  bool   `json:"mx_records"`
		SMTPServer bool   `json:"smtp_server"`
	} `json:"data"`
}

func (s *HunterSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	// Find domain-shaped variants for domain search
	domains := make([]string, 0)
	for _, v := range q.Variants {
		if IsDomain(v) && strings.Contains(v, ".") {
			tld := v[strings.LastIndex(v, "."):]
			if tld == ".com" || tld == ".io" || tld == ".co" || tld == ".net" || tld == ".org" {
				domains = append(domains, v)
			}
		}
	}

	// Email variants for verification
	emails := make([]string, 0)
	for _, v := range q.Variants {
		if IsEmail(v) {
			emails = append(emails, v)
		}
	}

	// Domain search: find email patterns and known contacts
	for _, domain := range domains[:min(len(domains), 3)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		findings, err := s.searchDomain(ctx, clients.Clear, cfg.HunterKey, domain)
		if err != nil {
			continue
		}
		for _, f := range findings {
			out <- f
			meta.Count++
		}
		time.Sleep(1 * time.Second)
	}

	// Email verification
	for _, email := range emails[:min(len(emails), 5)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		f, err := s.verifyEmail(ctx, clients.Clear, cfg.HunterKey, email)
		if err != nil || f == nil {
			continue
		}
		out <- *f
		meta.Count++
		time.Sleep(1 * time.Second)
	}

	return meta, nil
}

func (s *HunterSource) searchDomain(ctx context.Context, client *http.Client, apiKey, domain string) ([]result.Finding, error) {
	endpoint := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=10",
		url.QueryEscape(domain), apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hunter returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var data hunterDomainResp
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	var findings []result.Finding
	for _, e := range data.Data.Emails {
		sev := result.SeverityMedium
		if e.Confidence > 80 {
			sev = result.SeverityHigh
		}

		findings = append(findings, result.Finding{
			ID:      uuid.New().String(),
			Source:  "hunter",
			Variant: domain,
			Type:    "email",
			Title:   fmt.Sprintf("Email: %s", e.Value),
			Summary: fmt.Sprintf("%s %s · %s · %s · Confidence: %d%%",
				e.FirstName, e.LastName, e.Position, data.Data.Organization, e.Confidence),
			URL:      fmt.Sprintf("https://hunter.io/verify/%s", e.Value),
			Severity: sev,
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"email":        e.Value,
				"first_name":   e.FirstName,
				"last_name":    e.LastName,
				"position":     e.Position,
				"type":         e.Type,
				"confidence":   e.Confidence,
				"organization": data.Data.Organization,
				"domain":       domain,
				"pattern":      data.Data.Pattern,
				"linkedin":     e.LinkedIn,
			},
		})
	}
	return findings, nil
}

func (s *HunterSource) verifyEmail(ctx context.Context, client *http.Client, apiKey, email string) (*result.Finding, error) {
	endpoint := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s",
		url.QueryEscape(email), apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var data hunterEmailVerifyResp
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	if data.Data.Status == "undeliverable" {
		return nil, nil
	}

	sev := result.SeverityLow
	if data.Data.Status == "valid" && data.Data.Score > 70 {
		sev = result.SeverityMedium
	}

	return &result.Finding{
		ID:      uuid.New().String(),
		Source:  "hunter",
		Variant: email,
		Type:    "email",
		Title:   fmt.Sprintf("Email Verified: %s", email),
		Summary: fmt.Sprintf("Status: %s · Score: %d · Webmail: %v · Disposable: %v",
			data.Data.Status, data.Data.Score, data.Data.Webmail, data.Data.Disposable),
		Severity: sev,
		FoundAt:  time.Now(),
		Raw: map[string]any{
			"email":       email,
			"status":      data.Data.Status,
			"score":       data.Data.Score,
			"webmail":     data.Data.Webmail,
			"disposable":  data.Data.Disposable,
			"mx_records":  data.Data.MXRecords,
			"smtp_server": data.Data.SMTPServer,
		},
	}, nil
}
