package fixprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultGitHubBaseURL = "https://api.github.com"
	defaultGitHubRepo    = "NixOS/nixpkgs"
	// githubFetchTimeout bounds one file fetch; the probe sweeps a handful of
	// refs serially and must stay comfortably inside a scan job's budget.
	githubFetchTimeout = 30 * time.Second
)

// GitHubFetcher is the default Fetcher: the GitHub contents API with the raw
// media type, so a single GET returns file bytes at any ref without a clone.
type GitHubFetcher struct {
	// BaseURL replaces https://api.github.com; tests point it at httptest.
	BaseURL string
	// Repo is "owner/name"; NixOS/nixpkgs when empty.
	Repo string
	// Token is sent as a Bearer token when non-empty. Unauthenticated works
	// but hits the 60-requests/hour anonymous rate limit quickly in CI.
	Token string
	// Client defaults to a fresh client with githubFetchTimeout.
	Client *http.Client
}

// NewGitHubFetcher builds the production fetcher, resolving the token from
// GITHUB_TOKEN then GH_TOKEN so both Actions and gh-CLI environments work.
func NewGitHubFetcher() *GitHubFetcher {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	return &GitHubFetcher{
		Token:  token,
		Client: &http.Client{Timeout: githubFetchTimeout},
	}
}

// FileAt implements Fetcher via GET /repos/{repo}/contents/{path}?ref={ref}
// with Accept: application/vnd.github.raw.
func (g *GitHubFetcher) FileAt(ctx context.Context, path, ref string) ([]byte, error) {
	base := strings.TrimRight(g.BaseURL, "/")
	if base == "" {
		base = defaultGitHubBaseURL
	}
	repo := g.Repo
	if repo == "" {
		repo = defaultGitHubRepo
	}
	endpoint := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", base, repo, escapePathSegments(path), url.QueryEscape(ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.raw")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: githubFetchTimeout}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if len(body) > 240 {
			body = body[:240]
		}
		return nil, fmt.Errorf("GitHub contents request %s@%s failed: %s: %s", path, ref, res.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, readErr
	}
	return body, nil
}

// escapePathSegments escapes each path segment while keeping the separators,
// which url.PathEscape alone would encode.
func escapePathSegments(p string) string {
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}
