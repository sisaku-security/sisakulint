package rules

import (
	"context"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

func TestDependencyReviewSettings(t *testing.T) {
	src := `on: pull_request
permissions: {contents: read}
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: TRUE
          vulnerability-check: false
          license-check: "False"
          allow-licenses: MIT
          comment-summary-in-pr: always
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: yes
          vulnerability-check: disable
          license-check: false
`
	got := qualityKinds(t, DependencyReviewSettingsID, src)
	want := []string{
		"dependency-review-settings.warn-only: warn-only is true",
		"dependency-review-settings.vulnerability-check-off: vulnerability-check is false",
		"dependency-review-settings.license-policy-off: license-check is false, so the license policy written is not checked",
		"dependency-review-settings.comment-without-permission: the step asks to write the summary of the dependency review as a comment on the pull request, but the GITHUB_TOKEN of the job is not given pull-requests: write",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("%v\nwant %v", got, want)
	}
}

// answer answers repo.default-token-write with v, and nothing else.
type answer struct{ v bool }

func (a answer) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	if _, ok := q.(facts.RepoDefaultTokenWrite); ok {
		b := []byte("false")
		if a.v {
			b = []byte("true")
		}
		return facts.RawAnswer{State: facts.StateFound, Value: b}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not answered"}
}

func TestDependencyReviewSettingsDefaultToken(t *testing.T) {
	src := `on: pull_request
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/dependency-review-action@v4
        with: {comment-summary-in-pr: on-failure}
`
	rep := qualityReport(t, DependencyReviewSettingsID, src, answer{false})
	if len(rep.QualityFindings) != 1 || rep.QualityFindings[0].Certainty != lint.CertaintyConfirmed {
		t.Errorf("restricted: %+v", rep.QualityFindings)
	}
	if rep := qualityReport(t, DependencyReviewSettingsID, src, answer{true}); len(rep.QualityFindings) != 0 {
		t.Errorf("permissive: %+v", rep.QualityFindings)
	}
}
