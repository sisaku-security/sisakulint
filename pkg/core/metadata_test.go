package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/remote"
	"gopkg.in/yaml.v3"
)

func TestActionMetadataParsesCompositeRunsSteps(t *testing.T) {
	t.Parallel()

	content := []byte(`
name: setup
runs:
  using: composite
  steps:
    - uses: actions/cache@v5
      if: always()
      with:
        path: ~/.pnpm-store
        key: Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}
        fail-on-cache-miss: true
`)

	var meta ActionMetadata
	if err := yaml.Unmarshal(content, &meta); err != nil {
		t.Fatalf("yaml.Unmarshal returned error: %v", err)
	}

	if meta.Runs == nil {
		t.Fatal("Runs metadata is nil")
	}
	if meta.Runs.Using != "composite" {
		t.Fatalf("Runs.Using = %q, want %q", meta.Runs.Using, "composite")
	}
	if len(meta.Runs.Steps) != 1 {
		t.Fatalf("len(Runs.Steps) = %d, want 1", len(meta.Runs.Steps))
	}

	step := meta.Runs.Steps[0]
	if step.Uses != "actions/cache@v5" {
		t.Fatalf("step.Uses = %q, want actions/cache@v5", step.Uses)
	}
	if step.If != "always()" {
		t.Fatalf("step.If = %q, want always()", step.If)
	}
	if got := step.With["key"]; got != "Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}" {
		t.Fatalf("step.With[key] = %q", got)
	}
	if got := step.With["fail-on-cache-miss"]; got != "true" {
		t.Fatalf("step.With[fail-on-cache-miss] = %q, want true", got)
	}
}

func TestParseRemoteActionSpecSupportsRootAndSubpathActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
		dir  string
	}{
		{
			name: "root action",
			spec: "owner/repo@main",
			dir:  ".",
		},
		{
			name: "subpath action",
			spec: "TanStack/config/.github/setup@main",
			dir:  ".github/setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRemoteActionSpec(tt.spec)
			if !ok {
				t.Fatalf("parseRemoteActionSpec(%q) returned !ok", tt.spec)
			}
			if got.owner != strings.Split(tt.spec, "/")[0] {
				t.Fatalf("owner = %q", got.owner)
			}
			if got.dir != tt.dir {
				t.Fatalf("dir = %q, want %q", got.dir, tt.dir)
			}
			if got.ref != "main" {
				t.Fatalf("ref = %q, want main", got.ref)
			}
		})
	}
}

func TestRemoteActionMetadataPathsSupportsRootAction(t *testing.T) {
	t.Parallel()

	got := remoteActionMetadataPaths(".")
	want := []string{"action.yml", "action.yaml"}
	if len(got) != len(want) {
		t.Fatalf("len(remoteActionMetadataPaths(.)) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remoteActionMetadataPaths(.)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseRemoteActionSpecRejectsAbsoluteActionPath(t *testing.T) {
	t.Parallel()

	if got, ok := parseRemoteActionSpec("owner/repo//absolute/path@main"); ok {
		t.Fatalf("parseRemoteActionSpec returned ok with absolute path: %#v", got)
	}
}

func TestRemoteActionsMetadataCacheDeferFetcherConstruction(t *testing.T) {
	t.Parallel()

	c := NewRemoteActionsMetadataCache(nil)
	if c.fetcher != nil {
		t.Fatal("fetcher should not be constructed eagerly by NewRemoteActionsMetadataCache")
	}

	// Local / docker / malformed specs must short-circuit before fetcher construction.
	for _, spec := range []string{
		"./local-action",
		"docker://alpine:3.18",
		"no-at-sign",
		"",
	} {
		if _, err := c.FindMetadata(spec); err != nil {
			t.Fatalf("FindMetadata(%q) returned error: %v", spec, err)
		}
		if c.fetcher != nil {
			t.Fatalf("fetcher must remain nil after FindMetadata(%q)", spec)
		}
	}
}

// --- retry / caching policy tests for RemoteActionsMetadataCache. A
// transient fetch failure must never be cached as "no metadata": that would
// silently disable every resolver-backed rule for the rest of the run and
// make lint results nondeterministic.

func newTestRemoteCache(fetch func(ctx context.Context, repo *remote.RepositoryInfo, filePath, ref string) ([]byte, error)) *RemoteActionsMetadataCache {
	c := NewRemoteActionsMetadataCache(nil)
	c.fetchFile = fetch
	c.sleep = func(time.Duration) {} // no backoff in tests
	return c
}

func notFoundErr() error {
	return &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}}
}

func TestRemoteCacheRetriesTransientErrorThenSucceeds(t *testing.T) {
	t.Parallel()

	calls := 0
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, filePath, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("dial tcp: i/o timeout")
		}
		if filePath == "action.yml" {
			return []byte("runs:\n  using: node20\n"), nil
		}
		return nil, notFoundErr()
	})

	meta, err := c.FindMetadata("owner/repo@v1")
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if meta == nil || meta.Runs == nil || meta.Runs.Using != "node20" {
		t.Fatalf("unexpected metadata: %v", meta)
	}
	// Cached: a second lookup must not fetch again.
	before := calls
	if _, err := c.FindMetadata("owner/repo@v1"); err != nil {
		t.Fatal(err)
	}
	if calls != before {
		t.Errorf("expected cache hit, but fetch was called again (%d -> %d)", before, calls)
	}
}

func TestRemoteCacheDefinitive404IsNegativeCached(t *testing.T) {
	t.Parallel()

	calls := 0
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, _, _ string) ([]byte, error) {
		calls++
		return nil, notFoundErr()
	})

	meta, err := c.FindMetadata("owner/repo@v1")
	if err != nil {
		t.Fatalf("definitive 404 must not be an error, got: %v", err)
	}
	if meta != nil {
		t.Fatalf("expected nil metadata, got %v", meta)
	}
	if calls != 2 { // action.yml + action.yaml, no retries for 404
		t.Errorf("expected 2 fetch calls, got %d", calls)
	}
	if _, err := c.FindMetadata("owner/repo@v1"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("404 must be cached; got %d fetch calls after second lookup", calls)
	}
}

func TestRemoteCacheTransientFailureIsNotSilentlyNil(t *testing.T) {
	t.Parallel()

	calls := 0
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, _, _ string) ([]byte, error) {
		calls++
		return nil, fmt.Errorf("dial tcp: i/o timeout")
	})

	meta, err := c.FindMetadata("owner/repo@v1")
	if err == nil {
		t.Fatal("exhausted transient retries must surface an error, not a silent nil")
	}
	if meta != nil {
		t.Fatalf("expected nil metadata, got %v", meta)
	}
	wantCalls := remoteMetadataFetchAttempts * 2 // both candidate paths per attempt
	if calls != wantCalls {
		t.Errorf("expected %d fetch calls, got %d", wantCalls, calls)
	}
	// Repeat lookups return the recorded error without re-burning the budget.
	if _, err2 := c.FindMetadata("owner/repo@v1"); err2 == nil {
		t.Fatal("expected recorded failure error on repeat lookup")
	}
	if calls != wantCalls {
		t.Errorf("repeat lookup must not fetch again: %d calls", calls)
	}
}

func TestRemoteCacheRateLimitAbortsWithoutRetryOrCaching(t *testing.T) {
	t.Parallel()

	calls := 0
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, _, _ string) ([]byte, error) {
		calls++
		return nil, &github.RateLimitError{}
	})

	if _, err := c.FindMetadata("owner/repo@v1"); err == nil {
		t.Fatal("expected rate-limit error")
	}
	if calls != 1 {
		t.Errorf("rate limit must abort immediately, got %d fetch calls", calls)
	}
	// Not recorded as failed: a later lookup (e.g. after the window resets)
	// is allowed to try again.
	if _, err := c.FindMetadata("owner/repo@v1"); err == nil {
		t.Fatal("expected rate-limit error on retry lookup")
	}
	if calls != 2 {
		t.Errorf("rate-limited spec must stay retryable, got %d fetch calls", calls)
	}
}

func TestRemoteCacheCircuitBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()

	calls := 0
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, _, _ string) ([]byte, error) {
		calls++
		return nil, fmt.Errorf("dial tcp: network is unreachable")
	})

	for i := 0; i < remoteMetadataBreakerThreshold; i++ {
		spec := fmt.Sprintf("owner/repo%d@v1", i)
		if _, err := c.FindMetadata(spec); err == nil {
			t.Fatalf("expected error for %s", spec)
		}
	}
	before := calls
	if _, err := c.FindMetadata("owner/last@v1"); !errors.Is(err, errRemoteMetadataCircuitOpen) {
		t.Fatalf("expected circuit-open error, got: %v", err)
	}
	if calls != before {
		t.Errorf("breaker open must fail fast without fetching, got %d extra calls", calls-before)
	}
}

func TestRemoteCacheSingleflightCollapsesConcurrentLookups(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	c := newTestRemoteCache(func(_ context.Context, _ *remote.RepositoryInfo, filePath, _ string) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		if filePath == "action.yml" {
			return []byte("runs:\n  using: node24\n"), nil
		}
		return nil, notFoundErr()
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta, err := c.FindMetadata("owner/repo@v1")
			if err != nil || meta == nil {
				t.Errorf("unexpected result: %v %v", meta, err)
			}
		}()
	}
	close(release)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("expected 1 collapsed fetch, got %d", calls)
	}
}
