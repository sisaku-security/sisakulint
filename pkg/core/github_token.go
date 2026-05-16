package core

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

// GitHubTokenEnvVars lists the environment variables consulted for a GitHub
// API token, in priority order. SISAKULINT_GITHUB_TOKEN takes precedence so
// that a tool-specific token can override an ambient CI token whose scope is
// inappropriate for sisakulint.
var GitHubTokenEnvVars = []string{
	"SISAKULINT_GITHUB_TOKEN",
	"GITHUB_TOKEN",
	"GH_TOKEN",
}

// ResolveGitHubToken returns the first non-empty token in (override,
// SISAKULINT_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN) along with the source
// label for diagnostics. An empty source means no token was found.
func ResolveGitHubToken(override string, lookup func(string) (string, bool)) (token, source string) {
	if override != "" {
		return override, "-github-token"
	}
	if lookup == nil {
		lookup = os.LookupEnv
	}
	for _, name := range GitHubTokenEnvVars {
		if v, ok := lookup(name); ok && v != "" {
			return v, name
		}
	}
	return "", ""
}

// NewGitHubClient builds a *github.Client. When token is non-empty the
// client is wrapped with an oauth2 source so every request carries
// Authorization: Bearer <token>, lifting the unauthenticated 60 req/h limit
// to the authenticated 5,000 req/h limit. An empty token returns a plain
// client that uses http.DefaultClient.
func NewGitHubClient(ctx context.Context, token string) *github.Client {
	if token == "" {
		return github.NewClient(http.DefaultClient)
	}
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return github.NewClient(oauth2.NewClient(ctx, src))
}

// ErrGitHubRateLimit is returned by autofixers that abort because the
// GitHub API rate limit has been exhausted. Callers can match it with
// errors.Is to distinguish the silent-truncation failure mode from a
// per-action lookup failure (404, malformed ref, etc.) and skip writing
// any partially-fixed file to disk.
var ErrGitHubRateLimit = errors.New("github api rate limit exceeded")

// IsGitHubRateLimitError reports whether err originates from a GitHub API
// 403/429 rate-limit response. It accepts both go-github's typed
// *github.RateLimitError / *github.AbuseRateLimitError and our sentinel
// ErrGitHubRateLimit so callers can wrap freely.
func IsGitHubRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrGitHubRateLimit) {
		return true
	}
	var rateErr *github.RateLimitError
	if errors.As(err, &rateErr) {
		return true
	}
	var abuseErr *github.AbuseRateLimitError
	if errors.As(err, &abuseErr) {
		return true
	}
	return false
}
