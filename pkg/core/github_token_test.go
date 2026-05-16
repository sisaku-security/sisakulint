package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v68/github"
)

func TestResolveGitHubToken(t *testing.T) {
	tests := []struct {
		name       string
		override   string
		env        map[string]string
		wantToken  string
		wantSource string
	}{
		{
			name:       "override beats every env var",
			override:   "flag-token",
			env:        map[string]string{"SISAKULINT_GITHUB_TOKEN": "sisaku", "GITHUB_TOKEN": "ci", "GH_TOKEN": "gh"},
			wantToken:  "flag-token",
			wantSource: "-github-token",
		},
		{
			name:       "SISAKULINT_GITHUB_TOKEN preferred over GITHUB_TOKEN and GH_TOKEN",
			env:        map[string]string{"SISAKULINT_GITHUB_TOKEN": "sisaku", "GITHUB_TOKEN": "ci", "GH_TOKEN": "gh"},
			wantToken:  "sisaku",
			wantSource: "SISAKULINT_GITHUB_TOKEN",
		},
		{
			name:       "GITHUB_TOKEN preferred over GH_TOKEN",
			env:        map[string]string{"GITHUB_TOKEN": "ci", "GH_TOKEN": "gh"},
			wantToken:  "ci",
			wantSource: "GITHUB_TOKEN",
		},
		{
			name:       "GH_TOKEN used when only one set",
			env:        map[string]string{"GH_TOKEN": "gh"},
			wantToken:  "gh",
			wantSource: "GH_TOKEN",
		},
		{
			name:       "empty env value treated as unset (skip to next)",
			env:        map[string]string{"SISAKULINT_GITHUB_TOKEN": "", "GITHUB_TOKEN": "ci"},
			wantToken:  "ci",
			wantSource: "GITHUB_TOKEN",
		},
		{
			name:       "no token anywhere returns empty source",
			wantToken:  "",
			wantSource: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				v, ok := tt.env[key]
				return v, ok
			}
			gotToken, gotSource := ResolveGitHubToken(tt.override, lookup)
			if gotToken != tt.wantToken {
				t.Errorf("token = %q, want %q", gotToken, tt.wantToken)
			}
			if gotSource != tt.wantSource {
				t.Errorf("source = %q, want %q", gotSource, tt.wantSource)
			}
		})
	}
}

// TestResolveGitHubToken_DefaultLookupUsesProcessEnv verifies that passing a
// nil lookup falls back to os.LookupEnv. We assert by setting a per-test env
// var; the t.Setenv call also restores the prior value on teardown.
func TestResolveGitHubToken_DefaultLookupUsesProcessEnv(t *testing.T) {
	t.Setenv("SISAKULINT_GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "from-process")
	got, source := ResolveGitHubToken("", nil)
	if got != "from-process" {
		t.Errorf("token = %q, want %q", got, "from-process")
	}
	if source != "GITHUB_TOKEN" {
		t.Errorf("source = %q, want %q", source, "GITHUB_TOKEN")
	}
}

func TestNewGitHubClient_AttachesAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewGitHubClient(context.Background(), "secret-token")
	baseURL, _ := url.Parse(srv.URL + "/")
	client.BaseURL = baseURL

	req, err := client.NewRequest(http.MethodGet, "rate_limit", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := client.Do(context.Background(), req, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

func TestNewGitHubClient_NoTokenSendsNoAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewGitHubClient(context.Background(), "")
	baseURL, _ := url.Parse(srv.URL + "/")
	client.BaseURL = baseURL

	req, err := client.NewRequest(http.MethodGet, "rate_limit", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := client.Do(context.Background(), req, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

func TestIsGitHubRateLimitError(t *testing.T) {
	errResp429 := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}},
		Message:  "rate limit",
	}
	errResp403Exhausted := &github.ErrorResponse{
		Response: &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"X-Ratelimit-Remaining": []string{"0"}},
		},
		Message: "rate limit",
	}
	errResp403Other := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}},
		Message:  "forbidden for some other reason",
	}
	errResp404 := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}},
		Message:  "not found",
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
		{name: "sentinel", err: ErrGitHubRateLimit, want: true},
		{name: "wrapped sentinel", err: fmt.Errorf("context: %w", ErrGitHubRateLimit), want: true},
		{name: "RateLimitError", err: &github.RateLimitError{Message: "rate limit"}, want: true},
		{name: "wrapped RateLimitError", err: fmt.Errorf("context: %w", &github.RateLimitError{Message: "rate limit"}), want: true},
		{name: "AbuseRateLimitError", err: &github.AbuseRateLimitError{Message: "abuse"}, want: true},
		{name: "ErrorResponse 429", err: errResp429, want: true},
		{name: "ErrorResponse 403 with X-RateLimit-Remaining: 0", err: errResp403Exhausted, want: true},
		{name: "ErrorResponse 403 unrelated", err: errResp403Other, want: false},
		{name: "ErrorResponse 404", err: errResp404, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGitHubRateLimitError(tt.err); got != tt.want {
				t.Errorf("IsGitHubRateLimitError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
