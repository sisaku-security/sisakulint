package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

func TestNewSecretInLogRule(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()
	if rule.RuleName != "secret-in-log" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-in-log")
	}
	if !strings.Contains(rule.RuleDesc, "log") {
		t.Errorf("RuleDesc should mention 'log', got %q", rule.RuleDesc)
	}
}

func TestSecretInLog_CollectSecretEnvVars(t *testing.T) {
	t.Parallel()

	env := &ast.Env{
		Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API_TOKEN }}"},
			},
			"other": {
				Name:  &ast.String{Value: "OTHER"},
				Value: &ast.String{Value: "${{ github.event.inputs.x }}"},
			},
		},
	}

	rule := NewSecretInLogRule()
	got := rule.collectSecretEnvVars(env)

	if len(got) != 1 {
		t.Fatalf("expected 1 secret env var, got %d: %v", len(got), got)
	}
	if got["TOKEN"] != "secrets.API_TOKEN" {
		t.Errorf("expected TOKEN -> secrets.API_TOKEN, got %q", got["TOKEN"])
	}
}

func parseShellForTest(t *testing.T, script string) *syntax.File {
	t.Helper()
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		t.Fatalf("failed to parse shell script: %v", err)
	}
	return file
}

func TestSecretInLog_PropagateTaint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		initial  map[string]string
		expected map[string]bool // 期待される tainted 変数名
	}{
		{
			name: "command substitution with jq",
			script: `PRIVATE_KEY=$(echo "$GCP_KEY" | jq -r '.private_key')
echo "$PRIVATE_KEY"`,
			initial:  map[string]string{"GCP_KEY": "secrets.GCP"},
			expected: map[string]bool{"GCP_KEY": true, "PRIVATE_KEY": true},
		},
		{
			name: "chained assignment",
			script: `STEP1="$TOKEN"
STEP2=$(echo "$STEP1")`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true, "STEP1": true, "STEP2": true},
		},
		{
			name: "untainted variables stay untainted",
			script: `MSG="hello"
SAFE=$(date)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
		{
			name: "assignment from untainted source does not taint",
			script: `NOT_TAINTED=$(ls /tmp)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			got := rule.propagateTaint(file, tc.initial)
			if len(got) != len(tc.expected) {
				t.Fatalf("tainted set size = %d (%v), want %d (%v)", len(got), got, len(tc.expected), tc.expected)
			}
			for name := range tc.expected {
				if _, ok := got[name]; !ok {
					t.Errorf("expected %q to be tainted, was not. got=%v", name, got)
				}
			}
		})
	}
}
