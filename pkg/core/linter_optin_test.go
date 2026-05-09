package core

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinter_MissingTimeoutMinutesIsOptIn(t *testing.T) {
	t.Parallel()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	fixture := filepath.Join(repoRoot, "script", "actions", "timeout-minutes.yaml")
	content, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	hasTimeoutErr := func(t *testing.T, errs []*LintingError) bool {
		t.Helper()
		for _, e := range errs {
			// LintingError.Type carries the rule name (see pkg/core/errorformatter.go).
			if e.Type == "missing-timeout-minutes" {
				return true
			}
		}
		return false
	}

	t.Run("default (opt-in disabled): missing-timeout-minutes is suppressed", func(t *testing.T) {
		opts := &LinterOptions{LogOutputDestination: io.Discard}
		linter, err := NewLinter(bytes.NewBuffer(nil), opts)
		if err != nil {
			t.Fatalf("NewLinter: %v", err)
		}
		result, err := linter.Lint(fixture, content, nil)
		if err != nil {
			t.Fatalf("Lint: %v", err)
		}
		if hasTimeoutErr(t, result.Errors) {
			t.Errorf("missing-timeout-minutes should be suppressed by default; got errors: %v", result.Errors)
		}
	})

	t.Run("with -enable-rule missing-timeout-minutes: errors are emitted", func(t *testing.T) {
		opts := &LinterOptions{
			LogOutputDestination: io.Discard,
			EnabledOptInRules:    []string{"missing-timeout-minutes"},
		}
		linter, err := NewLinter(bytes.NewBuffer(nil), opts)
		if err != nil {
			t.Fatalf("NewLinter: %v", err)
		}
		result, err := linter.Lint(fixture, content, nil)
		if err != nil {
			t.Fatalf("Lint: %v", err)
		}
		if !hasTimeoutErr(t, result.Errors) {
			t.Errorf("missing-timeout-minutes should be emitted when enabled; got: %v", result.Errors)
		}
	})

	t.Run("unknown rule name produces an error", func(t *testing.T) {
		opts := &LinterOptions{
			LogOutputDestination: io.Discard,
			EnabledOptInRules:    []string{"no-such-rule"},
		}
		linter, err := NewLinter(bytes.NewBuffer(nil), opts)
		if err != nil {
			t.Fatalf("NewLinter: %v", err)
		}
		_, err = linter.Lint(fixture, content, nil)
		if err == nil {
			t.Fatal("expected error for unknown rule name, got nil")
		}
		if !strings.Contains(err.Error(), "no-such-rule") {
			t.Fatalf("error = %q, want substring %q", err.Error(), "no-such-rule")
		}
	})
}
