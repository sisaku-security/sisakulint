package rules

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// kvaFacts is a file of facts of the entries es, one a line.
func kvaFacts(t *testing.T, es ...string) facts.Resolver {
	t.Helper()
	s, err := facts.LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[` + strings.Join(es, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// kvaRun runs known-vulnerable-actions alone on the workflow src.
func kvaRun(t *testing.T, src string, r facts.Resolver) lint.Report {
	t.Helper()
	rep, _ := kvaRunIn(t, src, r)
	return rep
}

// kvaRunIn is kvaRun, and the inputs it ran on.
func kvaRunIn(t *testing.T, src string, r facts.Resolver) (lint.Report, lint.Inputs) {
	t.Helper()
	in, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath(".github/workflows/w.yml"), InputKind: lint.InputKindWorkflow, Bytes: []byte(src)})
	if err != nil {
		t.Fatal(err)
	}
	rep := runWith(t, KnownVulnerableActions, in, r)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	return rep, in
}

func kvaStep(uses string) string {
	return "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n"
}

const (
	kvaSHA      = "eaceaf801fd36c7dee90939fad912460b18a1ffe"
	kvaFixedSHA = "87c55149d96e628cc2ef7e6fc2aab372015aec85"
	kvaCxww     = `{"ghsa_id":"GHSA-cxww-7g56-2vh6","severity":"high","vulnerable_version_range":">= 4.0.0, < 4.1.3","first_patched_version":"4.1.3"}`
)

// kvaDownload are the facts of actions/download-artifact at v4.1.2, its
// commit tagged tags too.
func kvaDownload(tags ...string) []string {
	return []string{
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact"},"state":"found","value":[` + kvaCxww + `]}`,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact","version":"v4.1.2"},"state":"found","value":[` + kvaCxww + `]}`,
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"` + kvaSHA + `"},"state":"found","value":["` + strings.Join(tags, `","`) + `"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"actions/download-artifact","ref":"v4.1.3"},"state":"found","value":{"ref":"refs/tags/v4.1.3","sha":"` + kvaFixedSHA + `"}}`,
	}
}

func kvaKinds(rep lint.Report) string {
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, strings.TrimPrefix(f.Args.KindID().String(), "known-vulnerable-actions."))
	}
	for _, i := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, "?"+i.InconclusiveKind.String())
	}
	return strings.Join(out, " ")
}

// TestKnownVulnerableVersion: the version asked is the tag of the commit
// with the most numbers; v4, which GitHub reads as 4.0.0, is not asked
// when v4.1.2 points to the same commit.
func TestKnownVulnerableVersion(t *testing.T) {
	rep := kvaRun(t, kvaStep("actions/download-artifact@"+kvaSHA), kvaFacts(t, kvaDownload("refs/tags/v4", "refs/tags/v4.1.2")...))
	if kvaKinds(rep) != "advisory-high" {
		t.Fatalf("got %s", kvaKinds(rep))
	}
	if a := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(KnownVulnerableActionsAdvisoryHigh); a.Version.String() != "v4.1.2" {
		t.Errorf("version %s", a.Version)
	}
	for _, e := range rep.Facts {
		if q, ok := e.Query.(facts.PackageAdvisories); ok && q.Version.String() == "v4" {
			t.Error("asked v4")
		}
	}
}

// TestKnownVulnerableNoAdvisory: a package with no advisory asks nothing
// more of it; action.definition is asked of each uses, for the steps of a
// composite action.
func TestKnownVulnerableNoAdvisory(t *testing.T) {
	rep := kvaRun(t, kvaStep("actions/checkout@v4"), kvaFacts(t, `{"query":{"kind":"package.advisories","package":"actions/checkout"},"state":"found","value":[]}`))
	asked := slices.DeleteFunc(slices.Clone(rep.Facts), func(e facts.Entry) bool { return e.Query.Kind() == facts.KindActionDefinition })
	if kvaKinds(rep) != "" || len(asked) != 1 {
		t.Errorf("got %s, asked %d facts", kvaKinds(rep), len(asked))
	}
}

// TestKnownVulnerableUpperCase: a uses written in upper case is the same
// package (upstream's rule compared with case).
func TestKnownVulnerableUpperCase(t *testing.T) {
	rep := kvaRun(t, kvaStep("Actions/Download-Artifact@"+kvaSHA), kvaFacts(t, kvaDownload("refs/tags/v4.1.2")...))
	if kvaKinds(rep) != "advisory-high" {
		t.Errorf("got %s", kvaKinds(rep))
	}
}

// TestKnownVulnerableFix: the fix pins the commit of the fixed version and
// makes the comment its name, replacing the old one; on a
// tag there is none, for commit-sha pins the same place.
func TestKnownVulnerableFix(t *testing.T) {
	src := kvaStep("actions/download-artifact@" + kvaSHA + " # v4.1.2")
	r := kvaFacts(t, kvaDownload("refs/tags/v4.1.2")...)
	rep, in := kvaRunIn(t, src, r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil {
		t.Fatalf("got %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	reg, _ := lint.NewRegistry([]lint.Rule{KnownVulnerableActions})
	out, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out.Files[facts.MustCleanInputPath(".github/workflows/w.yml")])
	if !strings.Contains(got, "- uses: actions/download-artifact@"+kvaFixedSHA+" # v4.1.3\n") {
		t.Errorf("fixed:\n%s", got)
	}
	tag := kvaFacts(t, append(kvaDownload("refs/tags/v4.1.2"),
		`{"query":{"kind":"git.ref-commit","repo":"actions/download-artifact","ref":"v4.1.2"},"state":"found","value":{"ref":"refs/tags/v4.1.2","sha":"`+kvaSHA+`"}}`)...)
	rep = kvaRun(t, kvaStep("actions/download-artifact@v4.1.2"), tag)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || !strings.Contains(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Note, "commit-sha") {
		t.Errorf("on a tag: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestKnownVulnerableRanges: of the two ranges of GHSA-vqf5-2xx6-9wfm that
// GitHub gives for either version, the one that has the version is
// reported and fixed.
func TestKnownVulnerableRanges(t *testing.T) {
	const a = `{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"}`
	const b = `{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 2.26.11, < 3.0.0"}`
	sha3, sha2 := "d68b2d4edb4189fd2a5366ac14e72027bd4b37dd", strings.Repeat("2", 40)
	r := kvaFacts(t,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action"},"state":"found","value":[`+a+`,`+b+`]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action","version":"v3.28.2"},"state":"found","value":[`+a+`,`+b+`]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action","version":"v2.27.0"},"state":"found","value":[`+a+`,`+b+`]}`,
		`{"query":{"kind":"git.commit-tags","repo":"github/codeql-action","sha":"`+sha3+`"},"state":"found","value":["refs/tags/v3.28.2"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"github/codeql-action","sha":"`+sha2+`"},"state":"found","value":["refs/tags/v2.27.0"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"github/codeql-action","ref":"v3.28.3"},"state":"found","value":{"ref":"refs/tags/v3.28.3","sha":"dd196fa9ce80b6bacc74ca1c32bd5b0ba22efca7"}}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/analyze"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/analyze","version":"v3.28.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/analyze","version":"v2.27.0"},"state":"found","value":[]}`,
	)
	rep := kvaRun(t, kvaStep("github/codeql-action/analyze@"+sha3), r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(KnownVulnerableActionsAdvisoryHigh).VulnerableVersionRange != ">= 3.26.11, <= 3.28.2" {
		t.Errorf("v3.28.2: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep = kvaRun(t, kvaStep("github/codeql-action/analyze@"+sha2), r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(KnownVulnerableActionsAdvisoryHigh).VulnerableVersionRange != ">= 2.26.11, < 3.0.0" {
		t.Errorf("v2.27.0, whose range names no fix: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestKnownVulnerableJob: a reusable workflow of an advisory is read too
// (the upstream reads steps only).
func TestKnownVulnerableJob(t *testing.T) {
	sha := strings.Repeat("3", 40)
	adv := `{"ghsa_id":"GHSA-f9qj-7gh3-mhj4","severity":"high","vulnerable_version_range":"< 2.7.5","first_patched_version":"2.7.5"}`
	r := kvaFacts(t,
		`{"query":{"kind":"package.advisories","package":"kartverket/github-workflows"},"state":"found","value":[`+adv+`]}`,
		`{"query":{"kind":"package.advisories","package":"kartverket/github-workflows","version":"v2.7.4"},"state":"found","value":[`+adv+`]}`,
		`{"query":{"kind":"package.advisories","package":"kartverket/github-workflows/.github/workflows/run-terraform.yml"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"kartverket/github-workflows/.github/workflows/run-terraform.yml","version":"v2.7.4"},"state":"found","value":[]}`,
		`{"query":{"kind":"git.commit-tags","repo":"kartverket/github-workflows","sha":"`+sha+`"},"state":"found","value":["refs/tags/v2.7.4"]}`,
	)
	rep := kvaRun(t, "on: push\njobs:\n  plan:\n    uses: kartverket/github-workflows/.github/workflows/run-terraform.yml@"+sha+"\n", r)
	if kvaKinds(rep) != "advisory-high" {
		t.Errorf("got %s", kvaKinds(rep))
	}
}

// TestKnownVulnerableUnversioned: a branch whose head no version tag
// points to is inconclusive, not a version 0 (the upstream's u4).
func TestKnownVulnerableUnversioned(t *testing.T) {
	main := strings.Repeat("4", 40)
	r := kvaFacts(t,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact"},"state":"found","value":[`+kvaCxww+`]}`,
		`{"query":{"kind":"git.ref-commit","repo":"actions/download-artifact","ref":"main"},"state":"found","value":{"ref":"refs/heads/main","sha":"`+main+`"}}`,
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"`+main+`"},"state":"found","value":[]}`,
	)
	if got := kvaKinds(kvaRun(t, kvaStep("actions/download-artifact@main"), r)); got != "?version-unknown" {
		t.Errorf("got %s", got)
	}
}

// TestKnownVulnerableMajorOnly: a commit only a major tag names is
// inconclusive when a bound of a range lies within that major, and read
// when none does.
func TestKnownVulnerableMajorOnly(t *testing.T) {
	sha := strings.Repeat("5", 40)
	for _, c := range []struct {
		rng, want string
	}{
		{"< 2.7.5", "?version-unknown"}, // v2 may be 2.8.0: GitHub reads it as 2.0.0
		{"< 6", "advisory-high"},        // every 2.x.y is below 6
		{">= 3, < 4", ""},               // no 2.x.y is in it
	} {
		adv := `{"ghsa_id":"GHSA-f9qj-7gh3-mhj4","severity":"high","vulnerable_version_range":"` + c.rng + `"}`
		version := `[` + adv + `]`
		if c.want == "" {
			version = `[]`
		}
		r := kvaFacts(t,
			`{"query":{"kind":"package.advisories","package":"o/major"},"state":"found","value":[`+adv+`]}`,
			`{"query":{"kind":"package.advisories","package":"o/major","version":"v2"},"state":"found","value":`+version+`}`,
			`{"query":{"kind":"git.commit-tags","repo":"o/major","sha":"`+sha+`"},"state":"found","value":["refs/tags/v2"]}`,
		)
		if got := kvaKinds(kvaRun(t, kvaStep("o/major@"+sha), r)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.rng, got, c.want)
		}
	}
}

// TestKnownVulnerableUntaggedSHA: a SHA no version tag points to is
// inconclusive, not the version its digits make (the upstream's u5).
func TestKnownVulnerableUntaggedSHA(t *testing.T) {
	sha := "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"
	r := kvaFacts(t,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact"},"state":"found","value":[`+kvaCxww+`]}`,
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"`+sha+`"},"state":"found","value":[]}`,
	)
	if got := kvaKinds(kvaRun(t, kvaStep("actions/download-artifact@"+sha), r)); got != "?version-unknown" {
		t.Errorf("got %s", got)
	}
}

// TestKnownVulnerableFixInRange: the fix does not upgrade to a version in
// the range of another advisory of the package: it
// moves on to the first patched version of that advisory, and gives no fix
// when that advisory names no later version that fixes it (as the owner
// decided on 2026-11-13).
func TestKnownVulnerableFixInRange(t *testing.T) {
	for _, c := range []struct {
		name, other, want string
	}{
		{"moves on", `{"ghsa_id":"GHSA-g85v-wf27-67xc","severity":"low","vulnerable_version_range":">= 4.1.3, < 4.2.0","first_patched_version":"4.2.0"}`, "v4.2.0"},
		{"no later fix", `{"ghsa_id":"GHSA-g85v-wf27-67xc","severity":"low","vulnerable_version_range":">= 4.1.3"}`, ""},
	} {
		r := kvaFacts(t,
			`{"query":{"kind":"package.advisories","package":"actions/download-artifact"},"state":"found","value":[`+kvaCxww+`,`+c.other+`]}`,
			`{"query":{"kind":"package.advisories","package":"actions/download-artifact","version":"v4.1.2"},"state":"found","value":[`+kvaCxww+`]}`,
			`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"`+kvaSHA+`"},"state":"found","value":["refs/tags/v4.1.2"]}`,
			`{"query":{"kind":"git.ref-commit","repo":"actions/download-artifact","ref":"v4.2.0"},"state":"found","value":{"ref":"refs/tags/v4.2.0","sha":"`+strings.Repeat("6", 40)+`"}}`,
		)
		rep := kvaRun(t, kvaStep("actions/download-artifact@"+kvaSHA), r)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Fatalf("%s: got %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		switch {
		case c.want != "" && (f.Fix == nil || !strings.Contains(f.Fix.Title, c.want)):
			t.Errorf("%s: got fix %+v, no fix %+v, want a fix to %s", c.name, f.Fix, f.NoFix, c.want)
		case c.want == "" && (f.Fix != nil || f.NoFix == nil || !strings.Contains(f.NoFix.Note, "GHSA-g85v-wf27-67xc")):
			t.Errorf("%s: got fix %+v, no fix %+v", c.name, f.Fix, f.NoFix)
		}
	}
}

// TestKnownVulnerableFixKeepsPath: the fix of an action at a path keeps
// the path (the upstream's u6 drops it), and asks the advisories of the
// version only of the packages that have some.
func TestKnownVulnerableFixKeepsPath(t *testing.T) {
	const a = `{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"}`
	sha := "d68b2d4edb4189fd2a5366ac14e72027bd4b37dd"
	r := kvaFacts(t,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action"},"state":"found","value":[`+a+`]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action","version":"v3.28.2"},"state":"found","value":[`+a+`]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/init"},"state":"found","value":[]}`,
		`{"query":{"kind":"git.commit-tags","repo":"github/codeql-action","sha":"`+sha+`"},"state":"found","value":["refs/tags/v3.28.2"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"github/codeql-action","ref":"v3.28.3"},"state":"found","value":{"ref":"refs/tags/v3.28.3","sha":"dd196fa9ce80b6bacc74ca1c32bd5b0ba22efca7"}}`,
	)
	src := kvaStep("github/codeql-action/init@" + sha + " # v3.28.2")
	rep, in := kvaRunIn(t, src, r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil {
		t.Fatalf("got %+v %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
	reg, _ := lint.NewRegistry([]lint.Rule{KnownVulnerableActions})
	out, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out.Files[facts.MustCleanInputPath(".github/workflows/w.yml")]); !strings.Contains(got, "- uses: github/codeql-action/init@dd196fa9ce80b6bacc74ca1c32bd5b0ba22efca7 # v3.28.3\n") {
		t.Errorf("fixed:\n%s", got)
	}
}
