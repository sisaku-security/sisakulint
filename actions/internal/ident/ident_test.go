package ident

import "testing"

func TestIsKebab(t *testing.T) {
	for s, want := range map[string]bool{
		"code-injection": true, "a1-b2": true, "x": true,
		"": false, "Code": false, "1a": false, "a--b": false, "a-": false, "a_b": false, "a.b": false,
	} {
		if got := IsKebab(s); got != want {
			t.Errorf("IsKebab(%q) = %v", s, got)
		}
	}
}

func TestGoName(t *testing.T) {
	for s, want := range map[string]string{
		"fork-pr-author": "ForkPRAuthor", "test.repo-flag": "TestRepoFlag", "sha": "SHA",
		"git.ref-commit": "GitRefCommit", "run_id": "RunID", "url": "URL", "api": "API", "github": "GitHub", "N": "N",
		"ai-action-unsafe-sandbox": "AIActionUnsafeSandbox", "ghsa_id": "GHSAID", "ai-action-unrestricted-trigger.any-user": "AIActionUnrestrictedTriggerAnyUser",
	} {
		if got := GoName(s); got != want {
			t.Errorf("GoName(%q) = %q, want %q", s, got, want)
		}
	}
}
