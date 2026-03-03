package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TestImpostorCommitRuleFactory tests the ImpostorCommitRuleFactory constructor.
func TestImpostorCommitRuleFactory(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()

	if rule.RuleName != "impostor-commit" {
		t.Errorf("Expected RuleName to be 'impostor-commit', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects impostor commits that exist in the fork network but not in the repository's branches or tags"
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}

	if rule.commitCache == nil {
		t.Error("Expected commitCache to be initialized")
	}
	if rule.tagCache == nil {
		t.Error("Expected tagCache to be initialized")
	}
	if rule.branchCache == nil {
		t.Error("Expected branchCache to be initialized")
	}
	if rule.defaultBranchCache == nil {
		t.Error("Expected defaultBranchCache to be initialized")
	}
}

// TestIsFullSha tests the isFullSha function.
func TestIsFullSha(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ref      string
		expected bool
	}{
		{
			name:     "valid 40-char SHA lowercase",
			ref:      "a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: true,
		},
		{
			name:     "valid 40-char SHA with numbers",
			ref:      "1234567890abcdef1234567890abcdef12345678",
			expected: true,
		},
		{
			name:     "39-char SHA (too short)",
			ref:      "a81bbbf8298c0fa03ea29cdc473d45769f95367",
			expected: false,
		},
		{
			name:     "41-char SHA (too long)",
			ref:      "a81bbbf8298c0fa03ea29cdc473d45769f9536750",
			expected: false,
		},
		{
			name:     "uppercase SHA (invalid)",
			ref:      "A81BBBF8298C0FA03EA29CDC473D45769F953675",
			expected: false,
		},
		{
			name:     "mixed case SHA (invalid)",
			ref:      "A81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: false,
		},
		{
			name:     "semantic version",
			ref:      "v3",
			expected: false,
		},
		{
			name:     "full semantic version",
			ref:      "v3.5.2",
			expected: false,
		},
		{
			name:     "branch name",
			ref:      "main",
			expected: false,
		},
		{
			name:     "empty string",
			ref:      "",
			expected: false,
		},
		{
			name:     "SHA with non-hex characters",
			ref:      "g81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isFullSha(tt.ref)
			if result != tt.expected {
				t.Errorf("isFullSha(%q) = %v, want %v", tt.ref, result, tt.expected)
			}
		})
	}
}

// TestParseImpostorActionRef tests the parseImpostorActionRef function.
func TestParseImpostorActionRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		usesValue string
		wantOwner string
		wantRepo  string
		wantRef   string
		wantSkip  bool
	}{
		{
			name:      "standard action reference",
			usesValue: "actions/checkout@v4",
			wantOwner: "actions",
			wantRepo:  "checkout",
			wantRef:   "v4",
			wantSkip:  false,
		},
		{
			name:      "action with SHA",
			usesValue: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
			wantOwner: "actions",
			wantRepo:  "checkout",
			wantRef:   "a81bbbf8298c0fa03ea29cdc473d45769f953675",
			wantSkip:  false,
		},
		{
			name:      "nested path action",
			usesValue: "actions/aws/ec2@v1",
			wantOwner: "actions",
			wantRepo:  "aws",
			wantRef:   "v1",
			wantSkip:  false,
		},
		{
			name:      "local action with ./ prefix",
			usesValue: "./.github/actions/my-action",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
		{
			name:      "local action with .\\ prefix",
			usesValue: ".\\.github\\actions\\my-action",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
		{
			name:      "docker image",
			usesValue: "docker://alpine:3.18",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
		{
			name:      "missing @ symbol",
			usesValue: "actions/checkout",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
		{
			name:      "no slash in owner/repo",
			usesValue: "checkout@v4",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
		{
			name:      "empty string",
			usesValue: "",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantSkip:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			owner, repo, ref, skip := parseImpostorActionRef(tt.usesValue)
			if owner != tt.wantOwner {
				t.Errorf("parseImpostorActionRef(%q) owner = %q, want %q", tt.usesValue, owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("parseImpostorActionRef(%q) repo = %q, want %q", tt.usesValue, repo, tt.wantRepo)
			}
			if ref != tt.wantRef {
				t.Errorf("parseImpostorActionRef(%q) ref = %q, want %q", tt.usesValue, ref, tt.wantRef)
			}
			if skip != tt.wantSkip {
				t.Errorf("parseImpostorActionRef(%q) skip = %v, want %v", tt.usesValue, skip, tt.wantSkip)
			}
		})
	}
}

// TestImpostorCommitRule_VisitStep_SkipsNonShaRefs tests that non-SHA refs are skipped.
func TestImpostorCommitRule_VisitStep_SkipsNonShaRefs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		usesValue  string
		shouldSkip bool
	}{
		{
			name:       "tag reference - should skip",
			usesValue:  "actions/checkout@v4",
			shouldSkip: true,
		},
		{
			name:       "branch reference - should skip",
			usesValue:  "actions/checkout@main",
			shouldSkip: true,
		},
		{
			name:       "local action - should skip",
			usesValue:  "./.github/actions/test",
			shouldSkip: true,
		},
		{
			name:       "docker image - should skip",
			usesValue:  "docker://node:18",
			shouldSkip: true,
		},
		{
			name:       "short SHA - should skip (not full 40-char)",
			usesValue:  "actions/checkout@a81bbbf",
			shouldSkip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ImpostorCommitRuleFactory()
			step := &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: tt.usesValue,
						Pos:   &ast.Position{Line: 10, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			}

			err := rule.VisitStep(step)
			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}

			// Non-SHA refs should be skipped (no errors recorded)
			if tt.shouldSkip && len(rule.Errors()) != 0 {
				t.Errorf("Expected step to be skipped (no errors), but got %d error(s)", len(rule.Errors()))
			}
		})
	}
}

// TestImpostorCommitRule_VisitStep_RunCommand tests that run commands are skipped.
func TestImpostorCommitRule_VisitStep_RunCommand(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()
	step := &ast.Step{
		ID: &ast.String{Value: "run-test"},
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: "echo 'hello world'",
			},
		},
		Pos: &ast.Position{Line: 10, Col: 5},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) != 0 {
		t.Errorf("Expected no errors for run command, but got %d error(s)", len(rule.Errors()))
	}
}

// TestImpostorCommitRule_VisitStep_NilExec tests handling of nil Exec.
func TestImpostorCommitRule_VisitStep_NilExec(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()
	step := &ast.Step{
		ID:   &ast.String{Value: "test"},
		Exec: nil,
		Pos:  &ast.Position{Line: 10, Col: 5},
	}

	// Should not panic
	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) != 0 {
		t.Errorf("Expected no errors for nil Exec, but got %d error(s)", len(rule.Errors()))
	}
}

// TestImpostorCommitRule_GetGitHubClient tests that client is initialized once.
func TestImpostorCommitRule_GetGitHubClient(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()

	client1 := rule.getGitHubClient()
	client2 := rule.getGitHubClient()

	if client1 == nil {
		t.Error("Expected client to be initialized, got nil")
	}

	if client1 != client2 {
		t.Error("Expected same client instance on repeated calls")
	}
}

// TestImpostorCommitRule_CommitCaching tests that commit verification results are cached.
func TestImpostorCommitRule_CommitCaching(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()

	// Manually add a cached result
	cacheKey := "test/repo@abc123"
	cachedResult := &commitVerificationResult{
		isImpostor: false,
		latestTag:  "v1.0.0",
		err:        nil,
	}
	rule.commitCache[cacheKey] = cachedResult

	// Verify the cache is used
	result := rule.verifyCommit("test", "repo", "abc123")
	if result != cachedResult {
		t.Error("Expected cached result to be returned")
	}
}

// TestCommitVerificationResult tests the commitVerificationResult struct.
func TestCommitVerificationResult(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		result     *commitVerificationResult
		isImpostor bool
		latestTag  string
	}{
		{
			name: "valid commit",
			result: &commitVerificationResult{
				isImpostor: false,
				latestTag:  "v1.0.0",
				err:        nil,
			},
			isImpostor: false,
			latestTag:  "v1.0.0",
		},
		{
			name: "impostor commit",
			result: &commitVerificationResult{
				isImpostor: true,
				latestTag:  "v2.0.0",
				err:        nil,
			},
			isImpostor: true,
			latestTag:  "v2.0.0",
		},
		{
			name: "no latest tag",
			result: &commitVerificationResult{
				isImpostor: true,
				latestTag:  "",
				err:        nil,
			},
			isImpostor: true,
			latestTag:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.result.isImpostor != tt.isImpostor {
				t.Errorf("Expected isImpostor to be %v, got %v", tt.isImpostor, tt.result.isImpostor)
			}
			if tt.result.latestTag != tt.latestTag {
				t.Errorf("Expected latestTag to be %q, got %q", tt.latestTag, tt.result.latestTag)
			}
		})
	}
}

// TestImpostorCommitFixer_RuleNames tests the fixer's RuleNames method.
func TestImpostorCommitFixer_RuleNames(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()
	fixer := &impostorCommitFixer{
		rule:      rule,
		owner:     "actions",
		repo:      "checkout",
		latestTag: "v4",
	}

	if fixer.RuleNames() != "impostor-commit" {
		t.Errorf("Expected RuleNames() to be 'impostor-commit', got '%s'", fixer.RuleNames())
	}
}

// TestImpostorCommitRule_MultipleSteps tests processing multiple steps.
func TestImpostorCommitRule_MultipleSteps(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()

	// Pre-populate cache for testing
	rule.commitCache["actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"] = &commitVerificationResult{
		isImpostor: true,
		latestTag:  "v4",
	}
	rule.commitCache["actions/setup-node@cafebabecafebabecafebabecafebabecafebabe"] = &commitVerificationResult{
		isImpostor: true,
		latestTag:  "v4",
	}
	rule.commitCache["actions/cache@b4ffde65f46336ab88eb53be808477a3936bae11"] = &commitVerificationResult{
		isImpostor: false,
		latestTag:  "v4",
	}

	steps := []*ast.Step{
		{
			ID: &ast.String{Value: "impostor1"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
					Pos:   &ast.Position{Line: 10, Col: 5},
				},
			},
			Pos: &ast.Position{Line: 10, Col: 5},
		},
		{
			ID: &ast.String{Value: "impostor2"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/setup-node@cafebabecafebabecafebabecafebabecafebabe",
					Pos:   &ast.Position{Line: 15, Col: 5},
				},
			},
			Pos: &ast.Position{Line: 15, Col: 5},
		},
		{
			ID: &ast.String{Value: "valid"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/cache@b4ffde65f46336ab88eb53be808477a3936bae11",
					Pos:   &ast.Position{Line: 20, Col: 5},
				},
			},
			Pos: &ast.Position{Line: 20, Col: 5},
		},
		{
			ID: &ast.String{Value: "run-step"},
			Exec: &ast.ExecRun{
				Run: &ast.String{Value: "echo 'test'"},
			},
			Pos: &ast.Position{Line: 25, Col: 5},
		},
	}

	for _, step := range steps {
		err := rule.VisitStep(step)
		if err != nil {
			t.Errorf("VisitStep() returned unexpected error: %v", err)
		}
	}

	// Should have 2 errors (two impostor commits)
	expectedErrors := 2
	if len(rule.Errors()) != expectedErrors {
		t.Errorf("Expected %d errors, got %d", expectedErrors, len(rule.Errors()))
	}

	// Should have 2 auto-fixers (for impostor commits with latestTag)
	expectedAutoFixers := 2
	if len(rule.AutoFixers()) != expectedAutoFixers {
		t.Errorf("Expected %d auto-fixers, got %d", expectedAutoFixers, len(rule.AutoFixers()))
	}
}

// TestImpostorCommitRule_ErrorMessage tests that error messages contain expected content.
func TestImpostorCommitRule_ErrorMessage(t *testing.T) {
	t.Parallel()
	rule := ImpostorCommitRuleFactory()

	// Pre-populate cache
	sha := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	rule.commitCache["actions/checkout@"+sha] = &commitVerificationResult{
		isImpostor: true,
		latestTag:  "v4",
	}

	step := &ast.Step{
		ID: &ast.String{Value: "test"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: "actions/checkout@" + sha,
				Pos:   &ast.Position{Line: 42, Col: 10},
			},
		},
		Pos: &ast.Position{Line: 42, Col: 10},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) == 0 {
		t.Fatal("Expected error to be recorded")
	}

	errMsg := rule.Errors()[0].Error()

	expectedSubstrings := []string{
		"impostor-commit",
		"impostor commit",
		sha,
		"actions/checkout",
		"supply chain attack",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(errMsg, substr) {
			t.Errorf("Error message should contain '%s', got: %s", substr, errMsg)
		}
	}
}

// newTestGitHubClient creates a *github.Client pointing at the given test server URL.
func newTestGitHubClient(serverURL string) *github.Client {
	client := github.NewClient(nil)
	baseURL, _ := url.Parse(serverURL + "/")
	client.BaseURL = baseURL
	return client
}

// setTestClient injects a test client into the rule, ensuring that
// getGitHubClient() does not overwrite it via clientOnce.
func setTestClient(rule *ImpostorCommitRule, serverURL string) {
	rule.clientOnce.Do(func() {}) // exhaust Once so getGitHubClient won't overwrite
	rule.client = newTestGitHubClient(serverURL)
}

// TestImpostorCommitRule_getDefaultBranch tests getDefaultBranch with a mocked GitHub API.
func TestImpostorCommitRule_getDefaultBranch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		responseBody string
		statusCode   int
		wantBranch   string
	}{
		{
			name:         "returns default branch from API",
			responseBody: `{"default_branch": "main"}`,
			statusCode:   http.StatusOK,
			wantBranch:   "main",
		},
		{
			name:         "returns master when API says master",
			responseBody: `{"default_branch": "master"}`,
			statusCode:   http.StatusOK,
			wantBranch:   "master",
		},
		{
			name:         "falls back to main on API error",
			responseBody: `{"message": "Internal Server Error"}`,
			statusCode:   http.StatusInternalServerError,
			wantBranch:   "main",
		},
		{
			name:         "falls back to main when default_branch is empty",
			responseBody: `{"default_branch": ""}`,
			statusCode:   http.StatusOK,
			wantBranch:   "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			rule := ImpostorCommitRuleFactory()
			client := newTestGitHubClient(server.URL)
			branch := rule.getDefaultBranch(context.Background(), client, "owner", "repo")

			if branch != tt.wantBranch {
				t.Errorf("getDefaultBranch() = %q, want %q", branch, tt.wantBranch)
			}
		})
	}
}

// TestImpostorCommitRule_getDefaultBranch_UsesCache verifies the second call uses the cache.
func TestImpostorCommitRule_getDefaultBranch_UsesCache(t *testing.T) {
	t.Parallel()

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"default_branch": "develop"}`))
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	client := newTestGitHubClient(server.URL)
	ctx := context.Background()

	branch1 := rule.getDefaultBranch(ctx, client, "owner", "repo")
	branch2 := rule.getDefaultBranch(ctx, client, "owner", "repo")

	if branch1 != "develop" || branch2 != "develop" {
		t.Errorf("expected both calls to return 'develop', got %q and %q", branch1, branch2)
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call (cache hit on second), got %d", callCount)
	}
}

// TestImpostorCommitRule_isReachableFromBranch tests reachability with a mocked GitHub API.
func TestImpostorCommitRule_isReachableFromBranch(t *testing.T) {
	t.Parallel()

	const sha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"

	tests := []struct {
		name          string
		status        string
		httpStatus    int
		wantReachable bool
		wantErr       bool
	}{
		{
			name:          "behind means reachable",
			status:        "behind",
			httpStatus:    http.StatusOK,
			wantReachable: true,
		},
		{
			name:          "identical means reachable",
			status:        "identical",
			httpStatus:    http.StatusOK,
			wantReachable: true,
		},
		{
			name:          "ahead means not reachable",
			status:        "ahead",
			httpStatus:    http.StatusOK,
			wantReachable: false,
		},
		{
			name:          "diverged means not reachable",
			status:        "diverged",
			httpStatus:    http.StatusOK,
			wantReachable: false,
		},
		{
			name:       "API error is propagated",
			httpStatus: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.httpStatus)
				if tt.httpStatus == http.StatusOK {
					_, _ = fmt.Fprintf(w, `{"status":%q,"ahead_by":0,"behind_by":1,"commits":[],"files":[]}`, tt.status)
				} else {
					_, _ = w.Write([]byte(`{"message":"Internal Server Error"}`))
				}
			}))
			defer server.Close()

			rule := ImpostorCommitRuleFactory()
			client := newTestGitHubClient(server.URL)
			reachable, err := rule.isReachableFromBranch(context.Background(), client, "owner", "repo", "main", sha)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if reachable != tt.wantReachable {
				t.Errorf("isReachableFromBranch() = %v, want %v", reachable, tt.wantReachable)
			}
		})
	}
}

// TestImpostorCommitRule_getTags_ReturnsErrorOnFirstPageFailure tests that getTags
// returns an error when the first API page fails.
func TestImpostorCommitRule_getTags_ReturnsErrorOnFirstPageFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	client := newTestGitHubClient(server.URL)

	tags, err := rule.getTags(context.Background(), client, "owner", "repo")
	if err == nil {
		t.Fatal("expected error when first page fails, got nil")
	}
	if tags != nil {
		t.Errorf("expected nil tags on error, got %d tags", len(tags))
	}
	if !strings.Contains(err.Error(), "failed to fetch tags") {
		t.Errorf("expected error message to contain 'failed to fetch tags', got: %s", err.Error())
	}

	// Verify result was NOT cached
	rule.tagCacheMu.Lock()
	_, cached := rule.tagCache["owner/repo"]
	rule.tagCacheMu.Unlock()
	if cached {
		t.Error("expected error result to NOT be cached")
	}
}

// TestImpostorCommitRule_getTags_ReturnsCachedResult tests that getTags returns cached results.
func TestImpostorCommitRule_getTags_ReturnsCachedResult(t *testing.T) {
	t.Parallel()

	rule := ImpostorCommitRuleFactory()
	cachedTags := []*github.RepositoryTag{
		{Name: github.Ptr("v1.0.0")},
	}
	rule.tagCache["owner/repo"] = cachedTags

	// No server needed - should return from cache
	tags, err := rule.getTags(context.Background(), nil, "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tags) != 1 || tags[0].GetName() != "v1.0.0" {
		t.Errorf("expected cached tag v1.0.0, got %v", tags)
	}
}

// TestImpostorCommitRule_getBranches_ReturnsErrorOnFirstPageFailure tests that getBranches
// returns an error when the first API page fails.
func TestImpostorCommitRule_getBranches_ReturnsErrorOnFirstPageFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	client := newTestGitHubClient(server.URL)

	branches, err := rule.getBranches(context.Background(), client, "owner", "repo")
	if err == nil {
		t.Fatal("expected error when first page fails, got nil")
	}
	if branches != nil {
		t.Errorf("expected nil branches on error, got %d branches", len(branches))
	}
	if !strings.Contains(err.Error(), "failed to fetch branches") {
		t.Errorf("expected error message to contain 'failed to fetch branches', got: %s", err.Error())
	}

	// Verify result was NOT cached
	rule.branchCacheMu.Lock()
	_, cached := rule.branchCache["owner/repo"]
	rule.branchCacheMu.Unlock()
	if cached {
		t.Error("expected error result to NOT be cached")
	}
}

// TestImpostorCommitRule_getBranches_ReturnsCachedResult tests that getBranches returns cached results.
func TestImpostorCommitRule_getBranches_ReturnsCachedResult(t *testing.T) {
	t.Parallel()

	rule := ImpostorCommitRuleFactory()
	cachedBranches := []*github.Branch{
		{Name: github.Ptr("main")},
	}
	rule.branchCache["owner/repo"] = cachedBranches

	// No server needed - should return from cache
	branches, err := rule.getBranches(context.Background(), nil, "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 1 || branches[0].GetName() != "main" {
		t.Errorf("expected cached branch main, got %v", branches)
	}
}

// TestImpostorCommitRule_doVerifyCommit_FailOpenOnTagsError tests that doVerifyCommit
// returns isImpostor: false when getTags fails.
func TestImpostorCommitRule_doVerifyCommit_FailOpenOnTagsError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	rule.client = newTestGitHubClient(server.URL)

	result := rule.doVerifyCommit("owner", "repo", "a81bbbf8298c0fa03ea29cdc473d45769f953675")
	if result.isImpostor {
		t.Error("expected isImpostor to be false (fail open), but got true")
	}
	if result.err == nil {
		t.Error("expected error to be set")
	}
}

// TestImpostorCommitRule_doVerifyCommit_FailOpenOnBranchesError tests that doVerifyCommit
// returns isImpostor: false when getBranches fails (tags succeed but no SHA match).
func TestImpostorCommitRule_doVerifyCommit_FailOpenOnBranchesError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/tags") {
			// Tags API succeeds with a tag that doesn't match
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"name":"v1.0.0","commit":{"sha":"0000000000000000000000000000000000000000"}}]`))
		} else if strings.Contains(r.URL.Path, "/branches") {
			// Branches API fails
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	rule.client = newTestGitHubClient(server.URL)

	result := rule.doVerifyCommit("owner", "repo", "a81bbbf8298c0fa03ea29cdc473d45769f953675")
	if result.isImpostor {
		t.Error("expected isImpostor to be false (fail open on branch error), but got true")
	}
	if result.err == nil {
		t.Error("expected error to be set")
	}
}

// TestImpostorCommitRule_doVerifyCommit_FailOpenOnAllTagCompareFail tests that doVerifyCommit
// returns isImpostor: false when tags/branches succeed but all per-tag CompareCommits fail.
func TestImpostorCommitRule_doVerifyCommit_FailOpenOnAllTagCompareFail(t *testing.T) {
	t.Parallel()

	const testSha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"
	tagSha := "0000000000000000000000000000000000000000"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tags"):
			// Tags API succeeds with a tag that doesn't match
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `[{"name":"v1.0.0","commit":{"sha":"%s"}}]`, tagSha)
		case strings.Contains(path, "/branches"):
			// Branches API succeeds with empty list
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case strings.Contains(path, "/commits/"+testSha+"/branches-where-head"):
			// branches-where-head returns empty
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case strings.Contains(path, "/compare/"):
			// ALL CompareCommits calls fail (rate limited)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		case strings.HasSuffix(path, "/repos/owner/repo"):
			// getDefaultBranch
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	rule.client = newTestGitHubClient(server.URL)

	result := rule.doVerifyCommit("owner", "repo", testSha)
	if result.isImpostor {
		t.Error("expected isImpostor to be false (fail open when all tag comparisons fail), but got true")
	}
	if result.err == nil {
		t.Error("expected error to be set when all tag comparisons fail")
	}
}

// TestImpostorCommitRule_isBranchHead tests the isBranchHead method with various API responses.
func TestImpostorCommitRule_isBranchHead(t *testing.T) {
	t.Parallel()

	const testSha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantResult bool
		wantErr    bool
	}{
		{
			name:       "SHA is branch HEAD - single branch",
			statusCode: http.StatusOK,
			body:       `[{"name":"main","commit":{"sha":"` + testSha + `"}}]`,
			wantResult: true,
			wantErr:    false,
		},
		{
			name:       "SHA is branch HEAD - multiple branches",
			statusCode: http.StatusOK,
			body:       `[{"name":"main","commit":{"sha":"` + testSha + `"}},{"name":"stable","commit":{"sha":"` + testSha + `"}}]`,
			wantResult: true,
			wantErr:    false,
		},
		{
			name:       "SHA is not a branch HEAD - empty array",
			statusCode: http.StatusOK,
			body:       `[]`,
			wantResult: false,
			wantErr:    false,
		},
		{
			name:       "commit not found - 404",
			statusCode: http.StatusNotFound,
			body:       `{"message":"Not Found"}`,
			wantResult: false,
			wantErr:    false,
		},
		{
			name:       "server error - 500",
			statusCode: http.StatusInternalServerError,
			body:       `{"message":"Internal Server Error"}`,
			wantResult: false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/repos/owner/repo/commits/%s/branches-where-head", testSha)
				if r.URL.Path != expectedPath {
					t.Errorf("unexpected request path: %s, want %s", r.URL.Path, expectedPath)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			rule := ImpostorCommitRuleFactory()
			client := newTestGitHubClient(server.URL)

			result, err := rule.isBranchHead(context.Background(), client, "owner", "repo", testSha)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.wantResult {
				t.Errorf("isBranchHead() = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// TestImpostorCommitRule_NonDefaultBranchHead tests that a commit that is the HEAD
// of a non-default branch is NOT flagged as an impostor. The getBranches() fast-path
// should catch this before reaching the branches-where-head API.
func TestImpostorCommitRule_NonDefaultBranchHead(t *testing.T) {
	t.Parallel()

	const testSha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tags"):
			// No tags match the SHA
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"name":"v1.0.0","commit":{"sha":"0000000000000000000000000000000000000000"}}]`))
		case strings.Contains(path, "/branches"):
			// Branch list includes "stable" whose HEAD matches the test SHA
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `[{"name":"main","commit":{"sha":"1111111111111111111111111111111111111111"}},{"name":"stable","commit":{"sha":"%s"}}]`, testSha)
		default:
			// No other API should be called — if it is, the test should still pass
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	setTestClient(rule, server.URL)

	result := rule.doVerifyCommit("owner", "repo", testSha)
	if result.isImpostor {
		t.Error("expected isImpostor to be false for non-default branch HEAD, but got true")
	}
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
}

// TestImpostorCommitRule_ForkNetworkImpostor tests that a commit not found in any
// branch, tag, or via reachability is correctly flagged as an impostor.
func TestImpostorCommitRule_ForkNetworkImpostor(t *testing.T) {
	t.Parallel()

	const impostorSha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	const tagSha = "0000000000000000000000000000000000000000"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tags"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `[{"name":"v1.0.0","commit":{"sha":"%s"}}]`, tagSha)
		case strings.Contains(path, "/branches") && !strings.Contains(path, "/commits/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"name":"main","commit":{"sha":"1111111111111111111111111111111111111111"}}]`))
		case strings.Contains(path, "/branches-where-head"):
			// Not a branch HEAD
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		case strings.HasSuffix(path, "/repos/owner/repo"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case strings.Contains(path, "/compare/"):
			// SHA is diverged from all branches/tags — not reachable
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"diverged","ahead_by":1,"behind_by":0,"commits":[],"files":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	setTestClient(rule, server.URL)

	result := rule.doVerifyCommit("owner", "repo", impostorSha)
	if !result.isImpostor {
		t.Error("expected isImpostor to be true for fork network impostor commit, but got false")
	}
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
	if result.latestTag != "v1.0.0" {
		t.Errorf("expected latestTag to be 'v1.0.0', got %q", result.latestTag)
	}
}

// TestImpostorCommitRule_BranchHeadAPIUnavailable_FallthroughToReachability tests that
// when the branches-where-head API is unavailable (500), the rule falls through to
// the default branch reachability check and succeeds.
func TestImpostorCommitRule_BranchHeadAPIUnavailable_FallthroughToReachability(t *testing.T) {
	t.Parallel()

	const testSha = "a81bbbf8298c0fa03ea29cdc473d45769f953675"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tags"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"name":"v1.0.0","commit":{"sha":"0000000000000000000000000000000000000000"}}]`))
		case strings.Contains(path, "/branches-where-head"):
			// branches-where-head API unavailable
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"Internal Server Error"}`))
		case strings.Contains(path, "/branches") && !strings.Contains(path, "/commits/"):
			// Branch list — SHA doesn't match any branch HEAD
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"name":"main","commit":{"sha":"1111111111111111111111111111111111111111"}}]`))
		case strings.HasSuffix(path, "/repos/owner/repo"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case strings.Contains(path, "/compare/"):
			// SHA is reachable from main (behind = ancestor of main)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"behind","ahead_by":0,"behind_by":5,"commits":[],"files":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	rule := ImpostorCommitRuleFactory()
	setTestClient(rule, server.URL)

	result := rule.doVerifyCommit("owner", "repo", testSha)
	if result.isImpostor {
		t.Error("expected isImpostor to be false (reachability fallback should succeed), but got true")
	}
	if result.err != nil {
		t.Errorf("unexpected error: %v", result.err)
	}
}
