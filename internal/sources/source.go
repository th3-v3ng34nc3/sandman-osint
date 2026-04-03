package sources

import (
	"context"
	"math/rand"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// HTTPClients holds clearnet and optional Tor-proxied HTTP clients.
type HTTPClients struct {
	Clear *http.Client
	Tor   *http.Client // nil when Tor is unavailable
}

// Source is the interface every intelligence source must implement.
type Source interface {
	Name() string
	TargetTypes() []query.TargetType
	// IsAvailable returns false if the source cannot run (e.g. missing API key).
	IsAvailable(cfg config.Config) bool
	// Search executes the source against all relevant variants and sends findings
	// to out. It must respect ctx cancellation. It must not close out.
	Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error)
}

// Registry is the list of all sources, in priority order.
var Registry []Source

func init() {
	Registry = []Source{
		&HIBPSource{},
		&GitHubSource{},
		&ShodanSource{},
		&HunterSource{},
		&DuckDuckGoSource{},
		&UsernameSource{},
		&TorSource{},
	}
}

// BuildClients constructs HTTP clients for clearnet and (if configured) Tor.
func BuildClients(cfg config.Config) HTTPClients {
	clear := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	clients := HTTPClients{Clear: clear}

	if !cfg.Tor.Enabled {
		return clients
	}

	torClient, err := buildTorClient(cfg.Tor.SOCKSAddr)
	if err != nil {
		return clients
	}
	clients.Tor = torClient
	return clients
}

func buildTorClient(socksAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}, nil
}

// userAgents is a pool of common browser user-agent strings used for scraping.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// IsEmail returns true if s looks like an email address.
func IsEmail(s string) bool {
	at := indexOf(s, '@')
	return at > 0 && at < len(s)-1
}

// IsDomain returns true if s looks like a bare domain name.
func IsDomain(s string) bool {
	return indexOf(s, '.') >= 0 && indexOf(s, '@') < 0 && indexOf(s, ' ') < 0
}

func indexOf(s string, r byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == r {
			return i
		}
	}
	return -1
}
