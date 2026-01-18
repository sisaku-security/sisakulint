package core

import (
	"strings"
	"testing"

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
