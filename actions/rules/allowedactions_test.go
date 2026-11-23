package rules

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

const aaSHA = "0057852bfaa89a56745cba8c7296529d2fc39830"

// allowedActionsRun runs allowed-actions, named, on files of the repository
// repo (none without --repo), and gives each QualityFinding as its input,
// its kind and its uses, sorted; each must be confirmed.
func allowedActionsRun(t *testing.T, files map[string]string, repo string, r facts.Resolver) ([]string, lint.Report) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if repo != "" {
		if in.Repo, err = facts.ParseRepo(repo); err != nil {
			t.Fatal(err)
		}
	}
	all, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := lint.ParseSelector(AllowedActionsID.String())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := all.Select(lint.Only(sel), lint.FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, r)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	var out []string
	for _, f := range rep.QualityFindings {
		if f.Certainty != lint.CertaintyConfirmed {
			t.Errorf("%s: %v", f.Detected(), f.Certainty)
		}
		var a struct {
			Uses string `json:"uses"`
		}
		b, _ := json.Marshal(f.Args)
		json.Unmarshal(b, &a)
		out = append(out, f.Location.File.Input.String()+" "+f.Args.KindID().String()+" "+a.Uses)
	}
	slices.Sort(out)
	return out, rep
}

// settingFacts answers repo.allowed-actions of repo (no repo when empty)
// with the setting written as JSON.
func settingFacts(t *testing.T, repo, setting string) facts.Resolver {
	t.Helper()
	q := `{"kind":"repo.allowed-actions"}`
	if repo != "" {
		q = `{"kind":"repo.allowed-actions","repo":"` + repo + `"}`
	}
	return storeOf(t, `{"query":`+q+`,"state":"found","value":`+setting+`}`)
}

const selectedNone = `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":[],"sha_pinning_required":false}`

func TestAllowedActions(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": `on: push
jobs:
  a:
    runs-on: x
    container: busybox:1.36
    services:
      redis:
        image: redis:7
    steps:
      - uses: actions/checkout@` + aaSHA + `
      - if: false
        uses: actions/cache@` + aaSHA + `
      - uses: ./local
      - uses: $/local
      - uses: o/other@v1
      - uses: docker://alpine:3
  b:
    uses: x/y/.github/workflows/w.yml@v1
`,
		"local/action.yml": "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/cache@" + aaSHA + "\n    - uses: o/inside@v1\n",
	}
	got, rep := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", selectedNone))
	want := []string{
		".github/workflows/w.yml allowed-actions.unstarted-run actions/cache@" + aaSHA,
		".github/workflows/w.yml allowed-actions.unstarted-run actions/checkout@" + aaSHA,
		".github/workflows/w.yml allowed-actions.unstarted-run docker://alpine:3",
		".github/workflows/w.yml allowed-actions.unstarted-run x/y/.github/workflows/w.yml@v1",
		"local/action.yml allowed-actions.failed-job actions/cache@" + aaSHA,
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// the condition is the setting answered, as a value of JSON (the report
	// writes the keys in its own order)
	b, err := json.Marshal(rep.QualityFindings[0].Condition)
	var gotCond, wantCond any
	if err != nil || json.Unmarshal(b, &gotCond) != nil || json.Unmarshal([]byte(`{"query":{"kind":"repo.allowed-actions","repo":"o/r"},"eq":`+selectedNone+`}`), &wantCond) != nil {
		t.Fatalf("condition %s, %v", b, err)
	}
	if g, _ := json.Marshal(gotCond); string(g) != func() string { w, _ := json.Marshal(wantCond); return string(w) }() {
		t.Errorf("condition %s", b)
	}
	// all allows everything; local_only allows the owner only
	if got, _ := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", `{"allowed_actions":"all","sha_pinning_required":false}`)); len(got) != 0 {
		t.Errorf("all: %q", got)
	}
}

// TestAllowedActionsPinning: with sha_pinning_required, an action by a tag
// or a branch fails its job; an action by a full SHA, a Docker image and a
// reusable workflow by a branch do not.
func TestAllowedActionsPinning(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
      - uses: actions/cache@` + aaSHA + `
      - uses: docker://alpine:3.20
      - uses: ./ctag
  b:
    uses: x/y/.github/workflows/w.yml@main
`,
		"ctag/action.yml": "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n",
	}
	got, _ := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", `{"allowed_actions":"all","sha_pinning_required":true}`))
	want := []string{
		".github/workflows/w.yml allowed-actions.unpinned-action actions/cache@v4",
		"ctag/action.yml allowed-actions.unpinned-action actions/cache@v4",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// a uses that the setting neither allows nor finds pinned gets both
	// kinds, at the same place
	got, _ = allowedActionsRun(t, wfFile("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: bad/act@v1\n"), "o/r", settingFacts(t, "o/r", `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["!bad/*"],"sha_pinning_required":true}`))
	if want := []string{".github/workflows/w.yml allowed-actions.unpinned-action bad/act@v1", ".github/workflows/w.yml allowed-actions.unstarted-run bad/act@v1"}; !slices.Equal(got, want) {
		t.Errorf("both kinds: got %q, want %q", got, want)
	}
}

// TestAllowedActionsNoRepo: without --repo, no uses is of the owner of the
// repository, so a uses that only the owner would allow is reported
// (owner-unknown); an action of GitHub that the setting allows is not.
func TestAllowedActionsNoRepo(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: x/y@v1\n      - uses: actions/cache@" + aaSHA + "\n      - uses: bad/act@v1\n"
	got, _ := allowedActionsRun(t, wfFile(src), "", settingFacts(t, "", `{"allowed_actions":"selected","github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["!bad/*"],"sha_pinning_required":false}`))
	if want := []string{".github/workflows/w.yml allowed-actions.unstarted-run bad/act@v1", ".github/workflows/w.yml allowed-actions.unstarted-run x/y@v1"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestAllowedActionsEntryWithoutRepo: with --repo, an entry without repo
// does not answer the fact, so the rule reports nothing.
func TestAllowedActionsEntryWithoutRepo(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: x/y@v1\n"
	got, rep := allowedActionsRun(t, wfFile(src), "o/r", settingFacts(t, "", selectedNone))
	if len(got) != 0 || slices.Contains(rep.SkippedRules, AllowedActionsID) {
		t.Errorf("got %q, skipped %v", got, rep.SkippedRules)
	}
}

// TestAllowedActionsDefaultRun: the rule runs without --rule only when
// --facts or --fact answers repo.allowed-actions, not with --online alone.
func TestAllowedActionsDefaultRun(t *testing.T) {
	all, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		src  lint.FactSources
		runs bool
	}{
		{"no answer", lint.FactSources{}, false},
		{"--online", lint.FactSources{Online: true}, false},
		{"answered", lint.FactSources{AnsweredKinds: []facts.Kind{facts.KindRepoAllowedActions}}, true},
	} {
		reg, err := all.Select(lint.Selection{}, c.src)
		if err != nil {
			t.Fatal(err)
		}
		if skipped := slices.Contains(reg.Skipped(), AllowedActionsID); skipped == c.runs {
			t.Errorf("%s: skipped %v, want runs %v", c.name, skipped, c.runs)
		}
	}
}

// TestAllowedActionsRemoteComposite: the steps of a composite action of
// another repository that action.definition answers, as GitHub checks them
// with the setting of the repository of the run and fails the job (in a
// run that the authors of the rule made on GitHub,
// aquasecurity/trivy-action, which a pattern allowed, failed the job for
// its steps aquasecurity/setup-trivy and actions/cache). A step of the
// composite action by a tag is unpinned where the setting requires a full
// commit SHA; a docker:// step of it is not compared (composite-image).
func TestAllowedActionsRemoteComposite(t *testing.T) {
	content := "runs:\\n  using: composite\\n  steps:\\n    - uses: aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514\\n    - uses: actions/cache@" + aaSHA + "\\n    - uses: good/tagged@v2\\n    - uses: docker://busybox:1.36\\n    - uses: ./local\\n"
	def := `{"query":{"kind":"action.definition","repo":"aquasecurity/trivy-action","ref":"` + aaSHA + `"},"state":"found","value":{"commit":"` + aaSHA + `","file":"action.yml","content":"` + content + `","archive_substituted":false}}`
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: aquasecurity/trivy-action@" + aaSHA + "\n"
	setting := func(pinning string) string {
		return `{"query":{"kind":"repo.allowed-actions","repo":"o/r"},"state":"found","value":{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["aquasecurity/trivy-action@*","good/*"],"sha_pinning_required":` + pinning + `}}`
	}
	got, _ := allowedActionsRun(t, wfFile(src), "o/r", storeOf(t, def, setting("false")))
	want := []string{
		".github/workflows/w.yml allowed-actions.failed-job actions/cache@" + aaSHA,
		".github/workflows/w.yml allowed-actions.failed-job aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	got, _ = allowedActionsRun(t, wfFile(src), "o/r", storeOf(t, def, setting("true")))
	want = append(want, ".github/workflows/w.yml allowed-actions.unpinned-action good/tagged@v2")
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("pinning: got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
