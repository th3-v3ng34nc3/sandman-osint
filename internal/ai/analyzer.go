package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// provider identifies which AI backend to use.
type provider string

const (
	providerClaude provider = "claude"
	providerGemini provider = "gemini"
)

// Analyzer synthesises OSINT findings using an AI backend (Claude or Gemini).
type Analyzer struct {
	provider provider
	apiKey   string
	model    string
	client   *http.Client
}

// NewAnalyzer creates an Analyzer based on config.
// Provider selection:
//   - "claude"  → use Claude regardless
//   - "gemini"  → use Gemini regardless
//   - "auto"    → prefer Claude if key present, fall back to Gemini
//
// Returns nil if no usable key is configured.
func NewAnalyzer(cfg config.Config) *Analyzer {
	p, key, model := resolveProvider(cfg)
	if p == "" {
		return nil
	}
	return &Analyzer{
		provider: p,
		apiKey:   key,
		model:    model,
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func resolveProvider(cfg config.Config) (provider, string, string) {
	switch cfg.AIProvider {
	case "claude":
		if cfg.ClaudeKey != "" {
			return providerClaude, cfg.ClaudeKey, cfg.ClaudeModel
		}
		return "", "", ""
	case "gemini":
		if cfg.GeminiKey != "" {
			return providerGemini, cfg.GeminiKey, cfg.GeminiModel
		}
		return "", "", ""
	default: // "auto"
		if cfg.ClaudeKey != "" {
			return providerClaude, cfg.ClaudeKey, cfg.ClaudeModel
		}
		if cfg.GeminiKey != "" {
			return providerGemini, cfg.GeminiKey, cfg.GeminiModel
		}
		return "", "", ""
	}
}

// Provider returns the active provider name for display purposes.
func (a *Analyzer) Provider() string {
	if a == nil {
		return "none"
	}
	return string(a.provider)
}

// Analyze sends a condensed findings summary to the configured AI provider
// and returns structured intelligence analysis.
func (a *Analyzer) Analyze(ctx context.Context, q query.Query, findings []result.Finding) (*result.AIAnalysis, error) {
	if a == nil || len(findings) == 0 {
		return nil, nil
	}

	prompt := buildPrompt(q, findings)

	var (
		respText string
		err      error
	)
	switch a.provider {
	case providerGemini:
		respText, err = a.callGemini(ctx, prompt)
	default:
		respText, err = a.callClaude(ctx, prompt)
	}
	if err != nil {
		return nil, err
	}

	analysis := parseAnalysis(respText)
	analysis.RawResponse = respText
	return analysis, nil
}

// ─── Prompt & parser ─────────────────────────────────────────────────────────

const systemPrompt = "You are an OSINT analyst. Analyse the provided intelligence findings about a target " +
	"and produce a concise, structured assessment. Be factual and objective. " +
	"Avoid speculation beyond what the data supports."

const responseFormat = `

Please analyse these OSINT findings and respond in the following EXACT format (no markdown, no extra text):

RISK_SCORE: <integer 0-100>
SUMMARY: <2-3 sentence overall assessment>
KEY_FINDINGS:
- <finding 1>
- <finding 2>
- <finding 3>
CONNECTIONS:
- <cross-source connection 1>
- <cross-source connection 2>
`

func buildPrompt(q query.Query, findings []result.Finding) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TARGET: %q (type: %s)\n\n", q.Raw, q.Type))
	sb.WriteString(fmt.Sprintf("TOTAL FINDINGS: %d\n\n", len(findings)))
	sb.WriteString("FINDINGS SUMMARY:\n")

	bySource := make(map[string][]result.Finding)
	for _, f := range findings {
		bySource[f.Source] = append(bySource[f.Source], f)
	}

	for src, ff := range bySource {
		sb.WriteString(fmt.Sprintf("\n[%s] (%d findings)\n", strings.ToUpper(src), len(ff)))
		for _, f := range ff {
			sb.WriteString(fmt.Sprintf("  - [%s] %s: %s\n", f.Severity, f.Type, f.Title))
			if f.Summary != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", f.Summary))
			}
			if f.URL != "" {
				sb.WriteString(fmt.Sprintf("    URL: %s\n", f.URL))
			}
		}
	}

	sb.WriteString(responseFormat)
	return sb.String()
}

func parseAnalysis(text string) *result.AIAnalysis {
	a := &result.AIAnalysis{}
	lines := strings.Split(text, "\n")

	var inKeyFindings, inConnections bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "RISK_SCORE:"):
			s := strings.TrimSpace(strings.TrimPrefix(line, "RISK_SCORE:"))
			if n, err := strconv.Atoi(s); err == nil {
				a.RiskScore = clamp(n, 0, 100)
			}
			inKeyFindings, inConnections = false, false
		case strings.HasPrefix(line, "SUMMARY:"):
			a.Summary = strings.TrimSpace(strings.TrimPrefix(line, "SUMMARY:"))
			inKeyFindings, inConnections = false, false
		case line == "KEY_FINDINGS:":
			inKeyFindings, inConnections = true, false
		case line == "CONNECTIONS:":
			inConnections, inKeyFindings = true, false
		case strings.HasPrefix(line, "- ") && inKeyFindings:
			a.KeyFindings = append(a.KeyFindings, strings.TrimPrefix(line, "- "))
		case strings.HasPrefix(line, "- ") && inConnections:
			a.Connections = append(a.Connections, strings.TrimPrefix(line, "- "))
		}
	}

	if a.Summary == "" {
		a.Summary = text
	}
	return a
}

// ─── Claude ──────────────────────────────────────────────────────────────────

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []claudeMessage `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Analyzer) callClaude(ctx context.Context, userPrompt string) (string, error) {
	payload := claudeRequest{
		Model:     a.model,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages:  []claudeMessage{{Role: "user", Content: userPrompt}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("claude API returned %d: %s", resp.StatusCode, respBody)
	}

	var cr claudeResponse
	if err := json.Unmarshal(respBody, &cr); err != nil {
		return "", err
	}
	if cr.Error != nil {
		return "", fmt.Errorf("claude error: %s", cr.Error.Message)
	}
	for _, c := range cr.Content {
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("no text content in claude response")
}

// ─── Gemini ──────────────────────────────────────────────────────────────────

type geminiRequest struct {
	SystemInstruction *geminiContent    `json:"system_instruction,omitempty"`
	Contents          []geminiContent   `json:"contents"`
	GenerationConfig  geminiGenConfig   `json:"generationConfig"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens"`
	Temperature     float64 `json:"temperature"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Analyzer) callGemini(ctx context.Context, userPrompt string) (string, error) {
	endpoint := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		a.model, a.apiKey,
	)

	payload := geminiRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: systemPrompt}},
		},
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: userPrompt}}},
		},
		GenerationConfig: geminiGenConfig{
			MaxOutputTokens: 1024,
			Temperature:     0.3,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini API returned %d: %s", resp.StatusCode, respBody)
	}

	var gr geminiResponse
	if err := json.Unmarshal(respBody, &gr); err != nil {
		return "", err
	}
	if gr.Error != nil {
		return "", fmt.Errorf("gemini error %d: %s", gr.Error.Code, gr.Error.Message)
	}
	for _, c := range gr.Candidates {
		for _, p := range c.Content.Parts {
			if p.Text != "" {
				return p.Text, nil
			}
		}
	}
	return "", fmt.Errorf("no text content in gemini response")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
