package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
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
