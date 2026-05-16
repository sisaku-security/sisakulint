package core

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

// SISAKULINT_GITHUB_TOKEN is listed first so a tool-scoped token can override
// an ambient CI token whose scope is inappropriate for sisakulint.
var GitHubTokenEnvVars = []string{
	"SISAKULINT_GITHUB_TOKEN",
	"GITHUB_TOKEN",
	"GH_TOKEN",
}

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

func NewGitHubClient(ctx context.Context, token string) *github.Client {
	if token == "" {
		return github.NewClient(http.DefaultClient)
	}
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return github.NewClient(oauth2.NewClient(ctx, src))
}

var ErrGitHubRateLimit = errors.New("github api rate limit exceeded")

// IsGitHubRateLimitError covers both go-github's typed primary/secondary
// limit errors and plain 429 ErrorResponse fall-throughs that go-github does
// not classify (issue #474 codex review).
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
	var errResp *github.ErrorResponse
	if errors.As(err, &errResp) && errResp.Response != nil {
		switch errResp.Response.StatusCode {
		case http.StatusTooManyRequests:
			return true
		case http.StatusForbidden:
			if errResp.Response.Header.Get("X-RateLimit-Remaining") == "0" {
				return true
			}
		}
	}
	return false
}
