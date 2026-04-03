package config

import (
	"os"
	"strings"
)

// TorConfig holds Tor proxy settings.
type TorConfig struct {
	Enabled  bool
	SOCKSAddr string
}

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	ListenAddr   string
	HIBPKey      string
	HunterKey    string
	ShodanKey    string
	GitHubToken  string
	ClaudeKey    string
	ClaudeModel  string
	GeminiKey    string
	GeminiModel  string
	AIProvider   string // "claude" | "gemini" | "auto" (default: auto)
	Tor          TorConfig
}

// Load reads configuration from environment variables.
func Load() Config {
	return Config{
		ListenAddr:  normalizeAddr(getenv("PORT", "8080")),
		HIBPKey:     os.Getenv("SANDMAN_HIBP_KEY"),
		HunterKey:   os.Getenv("SANDMAN_HUNTER_KEY"),
		ShodanKey:   os.Getenv("SANDMAN_SHODAN_KEY"),
		GitHubToken: os.Getenv("SANDMAN_GITHUB_TOKEN"),
		ClaudeKey:   os.Getenv("SANDMAN_CLAUDE_KEY"),
		ClaudeModel: getenv("SANDMAN_CLAUDE_MODEL", "claude-opus-4-6"),
		GeminiKey:   os.Getenv("SANDMAN_GEMINI_KEY"),
		GeminiModel: getenv("SANDMAN_GEMINI_MODEL", "gemini-2.0-flash"),
		AIProvider:  getenv("SANDMAN_AI_PROVIDER", "auto"),
		Tor: TorConfig{
			Enabled:   os.Getenv("SANDMAN_TOR") == "1",
			SOCKSAddr: getenv("SANDMAN_TOR_ADDR", "127.0.0.1:9050"),
		},
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func normalizeAddr(s string) string {
	if !strings.HasPrefix(s, ":") {
		return ":" + s
	}
	return s
}
