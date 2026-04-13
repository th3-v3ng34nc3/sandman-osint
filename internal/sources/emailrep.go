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

// EmailRepSource checks email reputation via emailrep.io (free, no key required).
type EmailRepSource struct{}

func (s *EmailRepSource) Name() string { return "emailrep" }

func (s *EmailRepSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson}
}

func (s *EmailRepSource) IsAvailable(_ config.Config) bool { return true }

type emailRepResp struct {
	Email      string  `json:"email"`
	Reputation string  `json:"reputation"`
	Suspicious bool    `json:"suspicious"`
	References int     `json:"references"`
	Details    erDetails `json:"details"`
}

type erDetails struct {
	Blacklisted             bool     `json:"blacklisted"`
	MaliciousActivity       bool     `json:"malicious_activity"`
	CredentialsLeaked       bool     `json:"credentials_leaked"`
	CredentialsLeakedRecent bool     `json:"credentials_leaked_recent"`
	DataBreach              bool     `json:"data_breach"`
	FirstSeen               string   `json:"first_seen"`
	LastSeen                string   `json:"last_seen"`
	DomainExists            bool     `json:"domain_exists"`
	DomainReputation        string   `json:"domain_reputation"`
	Disposable              bool     `json:"disposable"`
	FreeProvider            bool     `json:"free_provider"`
	Deliverable             bool     `json:"deliverable"`
	Spoofable               bool     `json:"spoofable"`
	Profiles                []string `json:"profiles"`
}

func (s *EmailRepSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	var emails []string
	for _, v := range q.Variants {
		if IsEmail(v) {
			emails = append(emails, v)
		}
	}
	if len(emails) == 0 {
		return meta, nil
	}

	for _, email := range emails[:min(len(emails), 5)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		f, err := s.check(ctx, clients.Clear, email)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if f != nil {
			out <- *f
			meta.Count++
		}
		time.Sleep(1 * time.Second)
	}

	return meta, nil
}

func (s *EmailRepSource) check(ctx context.Context, client *http.Client, email string) (*result.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://emailrep.io/%s", email), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sandman-osint")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, nil // rate limited — skip gracefully
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emailrep returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var data emailRepResp
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	// Skip uninformative results
	if !data.Details.DataBreach && !data.Details.CredentialsLeaked &&
		!data.Suspicious && data.References < 5 && len(data.Details.Profiles) == 0 {
		return nil, nil
	}

	sev := result.SeverityLow
	if data.Details.DataBreach || data.Details.CredentialsLeaked {
		sev = result.SeverityHigh
	}
	if data.Details.CredentialsLeakedRecent || data.Suspicious || data.Details.MaliciousActivity {
		sev = result.SeverityCritical
	}

	parts := []string{fmt.Sprintf("reputation: %s", data.Reputation)}
	if data.References > 0 {
		parts = append(parts, fmt.Sprintf("%d references", data.References))
	}
	if len(data.Details.Profiles) > 0 {
		parts = append(parts, "profiles: "+strings.Join(data.Details.Profiles, ", "))
	}
	if data.Details.FirstSeen != "" {
		parts = append(parts, "first seen: "+data.Details.FirstSeen)
	}
	if data.Details.DataBreach {
		parts = append(parts, "data breach detected")
	}
	if data.Details.CredentialsLeaked {
		parts = append(parts, "credentials leaked")
	}

	return &result.Finding{
		ID:       uuid.New().String(),
		Source:   "emailrep",
		Variant:  email,
		Type:     "email",
		Title:    fmt.Sprintf("Email Reputation: %s", email),
		Summary:  strings.Join(parts, " · "),
		URL:      fmt.Sprintf("https://emailrep.io/%s", email),
		Severity: sev,
		FoundAt:  time.Now(),
		Raw: map[string]any{
			"email":                    email,
			"reputation":               data.Reputation,
			"suspicious":               data.Suspicious,
			"references":               data.References,
			"data_breach":              data.Details.DataBreach,
			"credentials_leaked":       data.Details.CredentialsLeaked,
			"credentials_leaked_recent": data.Details.CredentialsLeakedRecent,
			"profiles":                 data.Details.Profiles,
			"deliverable":              data.Details.Deliverable,
			"disposable":               data.Details.Disposable,
			"first_seen":               data.Details.FirstSeen,
			"last_seen":                data.Details.LastSeen,
		},
	}, nil
}
