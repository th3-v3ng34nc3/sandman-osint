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

// CRTShSource queries crt.sh certificate transparency logs for subdomain discovery.
type CRTShSource struct{}

func (s *CRTShSource) Name() string { return "crt.sh" }

func (s *CRTShSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetCompany, query.TargetPerson}
}

func (s *CRTShSource) IsAvailable(_ config.Config) bool { return true }

type crtEntry struct {
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

// interestingSubdomains are patterns that indicate high-value attack surface.
var interestingSubdomains = []string{
	"admin", "vpn", "mail", "api", "dev", "staging", "test", "internal",
	"portal", "login", "dashboard", "jenkins", "jira", "gitlab", "confluence",
	"kibana", "grafana", "monitor", "mx", "smtp", "ftp", "ssh", "rdp",
}

func (s *CRTShSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	var domains []string
	for _, v := range q.Variants {
		if IsDomain(v) {
			tld := v[strings.LastIndex(v, "."):]
			known := map[string]bool{
				".com": true, ".net": true, ".org": true, ".io": true,
				".co": true, ".app": true, ".dev": true, ".ai": true,
			}
			if known[tld] {
				domains = append(domains, v)
			}
		}
	}
	if len(domains) == 0 {
		return meta, nil
	}

	seen := make(map[string]bool)

	for _, domain := range domains[:min(len(domains), 3)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		entries, err := s.queryAPI(ctx, clients.Clear, domain)
		if err != nil {
			continue
		}

		for _, e := range entries {
			for _, name := range strings.Split(e.NameValue, "\n") {
				name = strings.TrimSpace(strings.ToLower(name))
				if name == "" || seen[name] {
					continue
				}
				if strings.HasPrefix(name, "*.") {
					name = name[2:]
				}
				seen[name] = true

				sev := result.SeverityLow
				sub := strings.SplitN(name, ".", 2)[0]
				for _, kw := range interestingSubdomains {
					if strings.Contains(sub, kw) {
						sev = result.SeverityHigh
						break
					}
				}

				expiry := ""
				if len(e.NotAfter) >= 10 {
					expiry = e.NotAfter[:10]
				}

				out <- result.Finding{
					ID:       uuid.New().String(),
					Source:   s.Name(),
					Variant:  domain,
					Type:     "domain",
					Title:    fmt.Sprintf("Subdomain: %s", name),
					Summary:  fmt.Sprintf("TLS cert by %s · expires %s", shortIssuer(e.IssuerName), expiry),
					URL:      fmt.Sprintf("https://crt.sh/?q=%s", url.QueryEscape(name)),
					Severity: sev,
					FoundAt:  time.Now(),
					Raw: map[string]any{
						"name":        name,
						"root_domain": domain,
						"issuer":      e.IssuerName,
						"not_before":  e.NotBefore,
						"not_after":   e.NotAfter,
					},
				}
				meta.Count++
			}
		}
		time.Sleep(1 * time.Second)
	}

	return meta, nil
}

func (s *CRTShSource) queryAPI(ctx context.Context, client *http.Client, domain string) ([]crtEntry, error) {
	endpoint := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", randomUA())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func shortIssuer(issuer string) string {
	if i := strings.Index(issuer, "O="); i >= 0 {
		rest := issuer[i+2:]
		if j := strings.Index(rest, ","); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return issuer
}
