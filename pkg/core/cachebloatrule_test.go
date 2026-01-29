package core

import (
	"strings"
	"testing"
)

func TestNewCacheBloatRule(t *testing.T) {
	t.Parallel()
	rule := NewCacheBloatRule()

	if rule.RuleName != "cache-bloat" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "cache-bloat")
	}
	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestIsCacheRestoreAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{"actions/cache/restore@v4 is restore action", "actions/cache/restore@v4", true},
		{"actions/cache/restore@v3 is restore action", "actions/cache/restore@v3", true},
		{"actions/cache/restore without version", "actions/cache/restore", true},
		{"actions/cache@v4 is not restore action", "actions/cache@v4", false},
		{"actions/cache/save@v4 is not restore action", "actions/cache/save@v4", false},
		{"actions/checkout@v4 is not restore action", "actions/checkout@v4", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isCacheRestoreAction(tt.uses)
			if got != tt.want {
				t.Errorf("isCacheRestoreAction(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

func TestIsCacheSaveAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{"actions/cache/save@v4 is save action", "actions/cache/save@v4", true},
		{"actions/cache/save@v3 is save action", "actions/cache/save@v3", true},
		{"actions/cache/save without version", "actions/cache/save", true},
		{"actions/cache@v4 is not save action", "actions/cache@v4", false},
		{"actions/cache/restore@v4 is not save action", "actions/cache/restore@v4", false},
		{"actions/checkout@v4 is not save action", "actions/checkout@v4", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isCacheSaveAction(tt.uses)
			if got != tt.want {
				t.Errorf("isCacheSaveAction(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

func TestHasProperRestoreCondition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"exact match: github.event_name != 'push'", "github.event_name != 'push'", true},
		{"double quotes: github.event_name != \"push\"", "github.event_name != \"push\"", true},
		{"with spaces", "github.event_name  !=  'push'", true},
		{"combined condition", "steps.cache.outputs.cache-hit != 'true' && github.event_name != 'push'", true},
		{"no condition", "", false},
		{"wrong operator: github.event_name == 'push'", "github.event_name == 'push'", false},
		{"wrong event: github.event_name != 'pull_request'", "github.event_name != 'pull_request'", false},
		{"unrelated condition", "always()", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasProperRestoreCondition(tt.condition)
			if got != tt.want {
				t.Errorf("hasProperRestoreCondition(%q) = %v, want %v", tt.condition, got, tt.want)
			}
		})
	}
}

func TestHasProperSaveCondition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{"exact match: github.event_name == 'push'", "github.event_name == 'push'", true},
		{"double quotes: github.event_name == \"push\"", "github.event_name == \"push\"", true},
		{"with spaces", "github.event_name  ==  'push'", true},
		{"combined condition", "steps.cache.outputs.cache-hit != 'true' && github.event_name == 'push'", true},
		{"no condition", "", false},
		{"wrong operator: github.event_name != 'push'", "github.event_name != 'push'", false},
		{"wrong event: github.event_name == 'pull_request'", "github.event_name == 'pull_request'", false},
		{"unrelated condition", "always()", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasProperSaveCondition(tt.condition)
			if got != tt.want {
				t.Errorf("hasProperSaveCondition(%q) = %v, want %v", tt.condition, got, tt.want)
			}
		})
	}
}

func TestCacheBloatRuleDetectsVulnerablePatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectedErrors int
		errorContains  []string
	}{
		{
			name: "both restore and save without conditions",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 2,
			errorContains:  []string{"cache/restore", "cache/save"},
		},
		{
			name: "only restore without condition (save has condition)",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 1,
			errorContains:  []string{"cache/restore"},
		},
		{
			name: "only save without condition (restore has condition)",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 1,
			errorContains:  []string{"cache/save"},
		},
		{
			name: "both have proper conditions - no errors",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 0,
			errorContains:  nil,
		},
		{
			name: "only restore exists (no save) - no errors",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
`,
			expectedErrors: 0,
			errorContains:  nil,
		},
		{
			name: "only save exists (no restore) - no errors",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 0,
			errorContains:  nil,
		},
		{
			name: "unified cache action - no errors",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: cache-key
      - run: echo "build"
`,
			expectedErrors: 0,
			errorContains:  nil,
		},
		{
			name: "multiple jobs - each checked independently",
			workflow: `
name: Test
on: [push, pull_request]
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: cache-key
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: cache-key
  job2:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with:
          path: ~/.cache
          key: cache-key
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with:
          path: ~/.cache
          key: cache-key
`,
			expectedErrors: 2, // Only job1 has errors
			errorContains:  []string{"cache/restore", "cache/save"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			workflow, errs := Parse([]byte(tt.workflow))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			rule := NewCacheBloatRule()
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Visit failed: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectedErrors, len(errors))
				for _, e := range errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			for _, contains := range tt.errorContains {
				found := false
				for _, e := range errors {
					if strings.Contains(e.Description, contains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing %q, but not found", contains)
				}
			}
		})
	}
}
