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

// GitHubSource searches GitHub for users and organisations.
type GitHubSource struct{}

func (s *GitHubSource) Name() string { return "github" }

func (s *GitHubSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *GitHubSource) IsAvailable(_ config.Config) bool { return true }

type ghUser struct {
	Login       string `json:"login"`
	Name        string `json:"name"`
	Bio         string `json:"bio"`
	Email       string `json:"email"`
	Blog        string `json:"blog"`
	Company     string `json:"company"`
	Location    string `json:"location"`
	PublicRepos int    `json:"public_repos"`
	Followers   int    `json:"followers"`
	Following   int    `json:"following"`
	CreatedAt   string `json:"created_at"`
	HTMLURL     string `json:"html_url"`
	AvatarURL   string `json:"avatar_url"`
	Type        string `json:"type"` // "User" or "Organization"
}

type ghSearchResult struct {
	TotalCount int      `json:"total_count"`
	Items      []ghUser `json:"items"`
}

func (s *GitHubSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}
	seen := make(map[string]bool)

	// Username-style variants only (no email or domain shapes)
	handles := make([]string, 0)
	for _, v := range q.Variants {
		if !IsEmail(v) && !IsDomain(v) && !strings.ContainsRune(v, ' ') {
			handles = append(handles, v)
		}
	}
	if len(handles) == 0 {
		handles = []string{q.Raw}
	}

	// Direct lookup first for the most likely handles
	for _, handle := range handles[:min(len(handles), 8)] {
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		default:
		}

		user, err := s.getUser(ctx, clients.Clear, cfg.GitHubToken, handle)
		if err != nil || user == nil {
			continue
		}
		if seen[user.Login] {
			continue
		}
		seen[user.Login] = true

		out <- ghFinding(user, handle)
		meta.Count++
		time.Sleep(300 * time.Millisecond)
	}

	// Search API for broader discovery
	searchTerms := []string{q.Raw}
	if q.Type == query.TargetCompany {
		searchTerms = append(searchTerms, handles[0])
	}

	for _, term := range searchTerms {
		results, err := s.searchUsers(ctx, clients.Clear, cfg.GitHubToken, term)
		if err != nil {
			continue
		}
		for _, u := range results {
			if seen[u.Login] {
				continue
			}
			seen[u.Login] = true
			out <- ghFinding(&u, term)
			meta.Count++
		}
		time.Sleep(500 * time.Millisecond)
	}

	return meta, nil
}

func (s *GitHubSource) getUser(ctx context.Context, client *http.Client, token, username string) (*ghUser, error) {
	endpoint := fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	setGHHeaders(req, token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var u ghUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *GitHubSource) searchUsers(ctx context.Context, client *http.Client, token, term string) ([]ghUser, error) {
	endpoint := fmt.Sprintf("https://api.github.com/search/users?q=%s&per_page=5", url.QueryEscape(term))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	setGHHeaders(req, token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var sr ghSearchResult
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, err
	}
	return sr.Items, nil
}

func setGHHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func ghFinding(u *ghUser, variant string) result.Finding {
	label := "User"
	if u.Type == "Organization" {
		label = "Organisation"
	}
	summary := fmt.Sprintf("@%s · %d repos · %d followers", u.Login, u.PublicRepos, u.Followers)
	if u.Bio != "" {
		summary += " · " + u.Bio
	}
	if u.Location != "" {
		summary += " · " + u.Location
	}

	sev := result.SeverityMedium
	if u.Followers > 1000 || u.Email != "" {
		sev = result.SeverityHigh
	}

	return result.Finding{
		ID:       uuid.New().String(),
		Source:   "github",
		Variant:  variant,
		Type:     "profile",
		Title:    fmt.Sprintf("GitHub %s: %s", label, u.Login),
		Summary:  summary,
		URL:      u.HTMLURL,
		Severity: sev,
		FoundAt:  time.Now(),
		Raw: map[string]any{
			"login":        u.Login,
			"name":         u.Name,
			"email":        u.Email,
			"bio":          u.Bio,
			"blog":         u.Blog,
			"company":      u.Company,
			"location":     u.Location,
			"public_repos": u.PublicRepos,
			"followers":    u.Followers,
			"created_at":   u.CreatedAt,
			"type":         u.Type,
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
