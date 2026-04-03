package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"sandman-osint/internal/config"
	"sandman-osint/internal/query"
	"sandman-osint/internal/result"
)

// UsernameSource checks a username across 60+ social platforms.
type UsernameSource struct{}

func (s *UsernameSource) Name() string { return "username" }

func (s *UsernameSource) TargetTypes() []query.TargetType {
	return []query.TargetType{query.TargetPerson, query.TargetUsername, query.TargetCompany}
}

func (s *UsernameSource) IsAvailable(_ config.Config) bool { return true }

// Platform defines how to check a username on a specific site.
type Platform struct {
	Name            string
	URLTemplate     string // {} is replaced with the username
	NotFoundStatus  int    // HTTP status indicating not found (usually 404)
	NotFoundContains string // body substring indicating not found
	FoundContains   string // body substring required to confirm found (optional)
	Severity        result.Severity
}

// platforms is the master list of supported sites.
var platforms = []Platform{
	// Development
	{Name: "GitHub", URLTemplate: "https://github.com/{}", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "GitLab", URLTemplate: "https://gitlab.com/{}", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "Bitbucket", URLTemplate: "https://bitbucket.org/{}/", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Dev.to", URLTemplate: "https://dev.to/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Hashnode", URLTemplate: "https://hashnode.com/@{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "CodePen", URLTemplate: "https://codepen.io/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "NPM", URLTemplate: "https://www.npmjs.com/~{}", NotFoundContains: "Not Found", Severity: result.SeverityLow},
	{Name: "PyPI", URLTemplate: "https://pypi.org/user/{}/", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Replit", URLTemplate: "https://replit.com/@{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "HuggingFace", URLTemplate: "https://huggingface.co/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "DockerHub", URLTemplate: "https://hub.docker.com/u/{}/", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "SourceForge", URLTemplate: "https://sourceforge.net/u/{}/profile/", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Social Media
	{Name: "Reddit", URLTemplate: "https://www.reddit.com/user/{}/about.json", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "Twitter/X", URLTemplate: "https://twitter.com/{}", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "Instagram", URLTemplate: "https://www.instagram.com/{}/", NotFoundContains: "Sorry, this page", Severity: result.SeverityHigh},
	{Name: "TikTok", URLTemplate: "https://www.tiktok.com/@{}", NotFoundContains: "Couldn't find this account", Severity: result.SeverityHigh},
	{Name: "Pinterest", URLTemplate: "https://www.pinterest.com/{}/", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Tumblr", URLTemplate: "https://{}.tumblr.com/", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Quora", URLTemplate: "https://www.quora.com/profile/{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Snapchat", URLTemplate: "https://www.snapchat.com/add/{}", NotFoundContains: "Sorry!", Severity: result.SeverityMedium},
	{Name: "Mastodon", URLTemplate: "https://mastodon.social/@{}", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Professional
	{Name: "LinkedIn", URLTemplate: "https://www.linkedin.com/in/{}", NotFoundContains: "Page not found", Severity: result.SeverityCritical},
	{Name: "AngelList", URLTemplate: "https://angel.co/{}", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "ProductHunt", URLTemplate: "https://www.producthunt.com/@{}", NotFoundStatus: 404, Severity: result.SeverityMedium},

	// Video / Streaming
	{Name: "YouTube", URLTemplate: "https://www.youtube.com/@{}", NotFoundStatus: 404, Severity: result.SeverityHigh},
	{Name: "Twitch", URLTemplate: "https://www.twitch.tv/{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Vimeo", URLTemplate: "https://vimeo.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Dailymotion", URLTemplate: "https://www.dailymotion.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Gaming
	{Name: "Steam", URLTemplate: "https://steamcommunity.com/id/{}", NotFoundContains: "The specified profile could not be found", Severity: result.SeverityMedium},
	{Name: "Roblox", URLTemplate: "https://www.roblox.com/users/profile?username={}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Bungie", URLTemplate: "https://www.bungie.net/7/en/User/Profile/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Speedrun.com", URLTemplate: "https://www.speedrun.com/users/{}", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Music
	{Name: "SoundCloud", URLTemplate: "https://soundcloud.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Spotify", URLTemplate: "https://open.spotify.com/user/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Bandcamp", URLTemplate: "https://{}.bandcamp.com/", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Last.fm", URLTemplate: "https://www.last.fm/user/{}", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Content / Blogging
	{Name: "Medium", URLTemplate: "https://medium.com/@{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Patreon", URLTemplate: "https://www.patreon.com/{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Substack", URLTemplate: "https://{}.substack.com/", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Ghost", URLTemplate: "https://{}.ghost.io/", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Crypto / Secure
	{Name: "Keybase", URLTemplate: "https://keybase.io/{}", NotFoundStatus: 404, Severity: result.SeverityHigh},

	// Photo / Media
	{Name: "Flickr", URLTemplate: "https://www.flickr.com/people/{}/", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Imgur", URLTemplate: "https://imgur.com/user/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "500px", URLTemplate: "https://500px.com/p/{}", NotFoundStatus: 404, Severity: result.SeverityLow},

	// Q&A / Forums
	{Name: "HackerNews", URLTemplate: "https://hacker-news.firebaseio.com/v0/user/{}.json", NotFoundContains: "null", Severity: result.SeverityHigh},
	{Name: "StackOverflow", URLTemplate: "https://stackoverflow.com/users/{}}", NotFoundStatus: 404, Severity: result.SeverityMedium},

	// Other
	{Name: "Gravatar", URLTemplate: "https://en.gravatar.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Duolingo", URLTemplate: "https://www.duolingo.com/profile/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Pastebin", URLTemplate: "https://pastebin.com/u/{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
	{Name: "Wattpad", URLTemplate: "https://www.wattpad.com/user/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Twitch Clips", URLTemplate: "https://clips.twitch.tv/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "About.me", URLTemplate: "https://about.me/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Linktree", URLTemplate: "https://linktr.ee/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Ko-fi", URLTemplate: "https://ko-fi.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Buy Me A Coffee", URLTemplate: "https://buymeacoffee.com/{}", NotFoundStatus: 404, Severity: result.SeverityLow},
	{Name: "Fiverr", URLTemplate: "https://www.fiverr.com/{}", NotFoundContains: "Fiverr - Page Not Found", Severity: result.SeverityMedium},
	{Name: "Upwork", URLTemplate: "https://www.upwork.com/freelancers/~{}", NotFoundStatus: 404, Severity: result.SeverityMedium},
}

const workerCount = 10

func (s *UsernameSource) Search(ctx context.Context, q query.Query, clients HTTPClients, cfg config.Config, out chan<- result.Finding) (result.SourceMeta, error) {
	meta := result.SourceMeta{Name: s.Name()}

	// Pick the best username variants (non-email, non-domain, no spaces)
	handles := make([]string, 0)
	for _, v := range q.Variants {
		if !IsEmail(v) && !IsDomain(v) && !strings.ContainsRune(v, ' ') {
			handles = append(handles, v)
		}
	}
	if len(handles) == 0 {
		handles = []string{strings.ReplaceAll(strings.ToLower(q.Raw), " ", "")}
	}

	// Only check the top 5 most likely handles to avoid spam
	checkHandles := handles
	if len(checkHandles) > 5 {
		checkHandles = checkHandles[:5]
	}

	type work struct {
		platform Platform
		username string
	}

	jobs := make(chan work, len(platforms)*len(checkHandles))
	for _, p := range platforms {
		for _, h := range checkHandles {
			jobs <- work{p, h}
		}
	}
	close(jobs)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				found, profileURL, err := checkPlatform(ctx, clients.Clear, job.platform, job.username)
				if err != nil || !found {
					continue
				}

				f := result.Finding{
					ID:       uuid.New().String(),
					Source:   "username",
					Variant:  job.username,
					Type:     "social",
					Title:    fmt.Sprintf("%s: %s", job.platform.Name, job.username),
					Summary:  fmt.Sprintf("Account found on %s", job.platform.Name),
					URL:      profileURL,
					Severity: job.platform.Severity,
					FoundAt:  time.Now(),
					Raw: map[string]any{
						"platform": job.platform.Name,
						"username": job.username,
						"url":      profileURL,
					},
				}

				mu.Lock()
				out <- f
				meta.Count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	return meta, nil
}

func checkPlatform(ctx context.Context, client *http.Client, p Platform, username string) (bool, string, error) {
	profileURL := strings.ReplaceAll(p.URLTemplate, "{}", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Use a shorter timeout for username checks
	checkClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := checkClient.Do(req)
	if err != nil {
		return false, "", nil // network error = unknown, treat as not found
	}
	defer resp.Body.Close()

	// Status-code-based not-found
	if p.NotFoundStatus != 0 && resp.StatusCode == p.NotFoundStatus {
		return false, "", nil
	}
	if resp.StatusCode >= 400 {
		return false, "", nil
	}

	// Content-based detection
	if p.NotFoundContains != "" || p.FoundContains != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // read max 64KB
		if err != nil {
			return false, "", nil
		}
		text := string(body)

		if p.NotFoundContains != "" && strings.Contains(text, p.NotFoundContains) {
			return false, "", nil
		}
		if p.FoundContains != "" && !strings.Contains(text, p.FoundContains) {
			return false, "", nil
		}
	}

	return true, profileURL, nil
}
