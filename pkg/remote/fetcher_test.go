package remote

import (
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewFetcherWithTokenSetsAPITimeout(t *testing.T) {
	fetcher, err := NewFetcherWithToken(1, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := fetcher.client.Client().Timeout; got != 2*time.Minute {
		t.Fatalf("API timeout = %s, want 2m", got)
	}
}

func TestTokenTransportRestrictsCredentialsToGitHubAPIHosts(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantAuth string
	}{
		{name: "GitHub API", host: "api.github.com", wantAuth: "Bearer test-token"},
		{name: "GitHub uploads", host: "uploads.github.com", wantAuth: "Bearer test-token"},
		{name: "custom host", host: "github.example.com", wantAuth: ""},
		{name: "archive host", host: "objects.githubusercontent.com", wantAuth: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuth string
			transport := &tokenTransport{
				token: "test-token",
				base: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					gotAuth = request.Header.Get("Authorization")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     make(http.Header),
						Body:       http.NoBody,
						Request:    request,
					}, nil
				}),
			}
			request, err := http.NewRequest(http.MethodGet, "https://"+tt.host+"/resource", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Basic original")
			if _, err := transport.RoundTrip(request); err != nil {
				t.Fatal(err)
			}
			if gotAuth != tt.wantAuth {
				t.Fatalf("Authorization = %q, want %q", gotAuth, tt.wantAuth)
			}
			if got := request.Header.Get("Authorization"); got != "Basic original" {
				t.Fatalf("original request header mutated to %q", got)
			}
		})
	}
}
