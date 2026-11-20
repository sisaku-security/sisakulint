package rules

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

const (
	dependabotSHA      = "0123456789abcdef0123456789abcdef01234567"
	dependabotUpperSHA = "0123456789ABCDEF0123456789ABCDEF01234567"
)

// dependabotFS is a repository whose workflow ci.yml and composite action
// build have uses the update tools update, and whose workflow none.yml has
// none of them.
var dependabotFS = fstest.MapFS{
	".github/workflows/ci.yml": {Data: []byte(`on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: a/b@v4
      - uses: a/c@` + dependabotSHA + `
      - uses: a/d@` + dependabotSHA + ` # v1.2.3
      - uses: a/e@` + dependabotSHA + ` # pinned for safety
      - uses: a/f@` + dependabotSHA + ` # ratchet:exclude
      - uses: a/g@abc1234
      - uses: ./local
      - uses: docker://alpine:3
      - uses: a/h@main
      - uses: a/i@` + dependabotUpperSHA + `
      - uses: ${{ 'a/j@v4' }}
      - uses: a/k@v4.1.0
      - uses: a/l@1.2
      - uses: a/m@20240101
  call:
    uses: o/r/.github/workflows/w.yml@v1
`)},
	".github/workflows/none.yml":       {Data: []byte("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local\n      - uses: a/h@main\n")},
	".github/actions/build/action.yml": {Data: []byte("name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: a/n@1.2\n")},
}

// dependabotAnswers answers the two facts of every input of dependabotFS:
// Dependabot, and Renovate (empty: not answered).
func dependabotAnswers(t *testing.T, dependabot, renovate string) facts.Resolver {
	t.Helper()
	var entries []string
	for _, p := range []string{".github/workflows/ci.yml", ".github/workflows/none.yml", ".github/actions/build/action.yml"} {
		if dependabot != "" {
			entries = append(entries, `{"query":{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":"`+p+`"},"state":"found","value":`+dependabot+`}`)
		}
		if renovate != "" {
			entries = append(entries, `{"query":{"kind":"renovate.manager-enabled","manager":"github-actions","input_path":"`+p+`"},"state":"found","value":`+renovate+`}`)
		}
	}
	return storeOf(t, entries...)
}

// dependabotFindings are the findings of rep, a line each: the file, the
// kind, the certainty, the place, the directory and the places of Related.
func dependabotFindings(rep lint.Report) []string {
	var out []string
	for _, f := range rep.QualityFindings {
		dir := ""
		switch a := f.Args.(type) {
		case DependabotGitHubActionsNoUpdateTool:
			dir = a.Directory
		case DependabotGitHubActionsUnversionedSHA:
			dir = a.Directory
		}
		var related []string
		for _, r := range f.Related {
			related = append(related, r.Location.KeyPath().String())
		}
		out = append(out, strings.Join([]string{f.Location.File.Input.String(), f.Args.KindID().String(), f.Certainty.String(), f.Location.KeyPath().String(), dir, strings.Join(related, " ")}, " | "))
	}
	slices.Sort(out)
	return out
}

func TestDependabotGitHubActions(t *testing.T) {
	const steps = "jobs.a.steps"
	counted := []string{steps + "[1].uses", steps + "[2].uses", steps + "[3].uses", steps + "[4].uses", steps + "[5].uses",
		steps + "[11].uses", steps + "[12].uses", steps + "[13].uses", "jobs.call.uses"}
	for _, c := range []struct {
		name, dependabot, renovate string
		want                       []string
	}{
		{"no update tool", "false", "false", []string{
			".github/actions/build/action.yml | dependabot-github-actions.no-update-tool | confirmed | runs.steps[0].uses | /.github/actions/build | ",
			".github/workflows/ci.yml | dependabot-github-actions.no-update-tool | confirmed | " + steps + "[0].uses | / | " + strings.Join(counted, " "),
		}},
		{"Renovate", "false", "true", []string{
			".github/workflows/ci.yml | dependabot-github-actions.unversioned-sha | confirmed | " + steps + "[1].uses | / | " + steps + "[3].uses " + steps + "[4].uses " + steps + "[5].uses",
		}},
		{"Dependabot", "true", "false", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := dependabotFindings(qualityReportFS(t, DependabotGitHubActionsID, dependabotFS, dependabotAnswers(t, c.dependabot, c.renovate)))
			if !slices.Equal(got, c.want) {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
	t.Run("no answer", func(t *testing.T) {
		rep := qualityReportFS(t, DependabotGitHubActionsID, dependabotFS, dependabotAnswers(t, "false", ""))
		var kinds []string
		for _, f := range rep.QualityFindings {
			if f.Location.File.Input.String() != ".github/workflows/ci.yml" {
				continue
			}
			kinds = append(kinds, f.Args.KindID().String()+" "+f.Certainty.String())
			var qs []string
			for _, q := range f.Condition.Queries() {
				b, _ := facts.EncodeQuery(q)
				qs = append(qs, string(b))
			}
			want := []string{
				`{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":".github/workflows/ci.yml"}`,
				`{"kind":"renovate.manager-enabled","manager":"github-actions","input_path":".github/workflows/ci.yml"}`,
			}
			if !slices.Equal(qs, want) {
				t.Errorf("queries %v", qs)
			}
		}
		slices.Sort(kinds)
		if want := []string{"dependabot-github-actions.no-update-tool conditional", "dependabot-github-actions.unversioned-sha conditional"}; !slices.Equal(kinds, want) {
			t.Errorf("got %v", kinds)
		}
	})
}

// TestDependabotTwoKindsAtOneUses: the two kinds at the same uses (the
// first uses is a SHA without a comment, and Renovate is not answered)
// have fingerprints of their own.
func TestDependabotTwoKindsAtOneUses(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/ci.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: a/b@" + dependabotSHA + "\n")}}
	rep := qualityReportFS(t, DependabotGitHubActionsID, fsys, storeOf(t))
	if len(rep.QualityFindings) != 2 || rep.QualityFindings[0].Fingerprint == rep.QualityFindings[1].Fingerprint {
		t.Errorf("%+v", rep.QualityFindings)
	}
}

// TestDependabotDirectory: the directory of the entry that reads a file.
func TestDependabotDirectory(t *testing.T) {
	for p, want := range map[string]string{
		".github/workflows/ci.yml":         "/",
		"action.yml":                       "/",
		"action.yaml":                      "/",
		".github/actions/build/action.yml": "/.github/actions/build",
		".github/workflows/sub/x.yml":      "/.github/workflows/sub",
		"ci.yml":                           "/",
	} {
		n, err := facts.ParseInputPath(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := dependabotDirectory(n); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
}

// TestRenovateVersionComment: the comments that Renovate reads as the
// version of a pinned SHA.
func TestRenovateVersionComment(t *testing.T) {
	for c, want := range map[string]bool{
		"v4.1.0": true, "tag=v4": true, "renovate: tag=v4.1.0": true, "pin @v4": true, "main": true, "4": true,
		"": false, "pinned for safety": false, "ratchet:exclude": false,
	} {
		if got := renovateVersionComment(c); got != want {
			t.Errorf("%q: %v", c, got)
		}
	}
}
