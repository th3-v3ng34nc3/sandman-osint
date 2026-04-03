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

// ShodanSource queries Shodan for network intelligence on domains and IPs.
type ShodanSource struct{}

func (s *ShodanSource) Name() string { return "shodan" }

func (s *ShodanSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetCompany, query.TargetPerson}
}

func (s *ShodanSource) IsAvailable(cfg config.Config) bool {
	return cfg.ShodanKey != ""
}

type shodanHost struct {
	IP       string   `json:"ip_str"`
	Org      string   `json:"org"`
	ISP      string   `json:"isp"`
	Country  string   `json:"country_name"`
	City     string   `json:"city"`
	OS       string   `json:"os"`
	Ports    []int    `json:"ports"`
	Vulns    []string `json:"vulns"`
	Hostnames []string `json:"hostnames"`
	Domains  []string `json:"domains"`
	Tags     []string `json:"tags"`
}

type shodanDNS struct {
	IP string `json:"ip"`
}

func (s *ShodanSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	// Find domain-shaped variants
	domains := make([]string, 0)
	for _, v := range q.Variants {
		if IsDomain(v) && strings.Contains(v, ".") {
			// Only real TLD-looking domains
			tld := v[strings.LastIndex(v, "."):]
			knownTLDs := map[string]bool{
				".com": true, ".net": true, ".org": true, ".io": true,
				".co": true, ".app": true, ".dev": true, ".ai": true,
			}
			if knownTLDs[tld] {
				domains = append(domains, v)
			}
		}
	}

	if len(domains) == 0 {
		return meta, nil
	}

	for _, domain := range domains[:min(len(domains), 5)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		// Resolve domain to IP
		ip, err := s.resolveDNS(ctx, clients.Clear, cfg.ShodanKey, domain)
		if err != nil || ip == "" {
			continue
		}

		// Look up the IP on Shodan
		host, err := s.lookupHost(ctx, clients.Clear, cfg.ShodanKey, ip)
		if err != nil {
			continue
		}

		sev := result.SeverityInfo
		if len(host.Ports) > 5 {
			sev = result.SeverityMedium
		}
		if len(host.Vulns) > 0 {
			sev = result.SeverityHigh
		}
		if len(host.Vulns) > 3 {
			sev = result.SeverityCritical
		}

		portStrs := make([]string, len(host.Ports))
		for i, p := range host.Ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}

		out <- result.Finding{
			ID:       uuid.New().String(),
			Source:   s.Name(),
			Variant:  domain,
			Type:     "network",
			Title:    fmt.Sprintf("Shodan: %s (%s)", domain, ip),
			Summary:  fmt.Sprintf("%s · %s, %s · Ports: %s · CVEs: %d", host.Org, host.City, host.Country, strings.Join(portStrs, ", "), len(host.Vulns)),
			URL:      fmt.Sprintf("https://www.shodan.io/host/%s", ip),
			Severity: sev,
			FoundAt:  time.Now(),
			Raw: map[string]any{
				"domain":    domain,
				"ip":        ip,
				"org":       host.Org,
				"isp":       host.ISP,
				"country":   host.Country,
				"city":      host.City,
				"os":        host.OS,
				"ports":     host.Ports,
				"vulns":     host.Vulns,
				"hostnames": host.Hostnames,
				"tags":      host.Tags,
			},
		}
		meta.Count++
		time.Sleep(1 * time.Second) // Shodan free tier rate limit
	}

	return meta, nil
}

func (s *ShodanSource) resolveDNS(ctx context.Context, client *http.Client, apiKey, domain string) (string, error) {
	endpoint := fmt.Sprintf("https://api.shodan.io/dns/resolve?hostnames=%s&key=%s",
		url.QueryEscape(domain), apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("shodan dns returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var resolved map[string]string
	if err := json.Unmarshal(body, &resolved); err != nil {
		return "", err
	}
	return resolved[domain], nil
}

func (s *ShodanSource) lookupHost(ctx context.Context, client *http.Client, apiKey, ip string) (*shodanHost, error) {
	endpoint := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
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
		return nil, fmt.Errorf("shodan host returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var host shodanHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, err
	}
	return &host, nil
}
