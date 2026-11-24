package rules

import (
	"context"
	"os"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

func callJob(uses, secrets string) string {
	return "on: push\njobs:\n  call:\n    uses: " + uses + "\n" + secrets
}

// TestSecretsInherit: the findings of secrets-inherit on calls with
// secrets: inherit.
func TestSecretsInherit(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []lint.FindingArgs
	}{
		{"remote", callJob("octo/shared/.github/workflows/d.yml@v1", "    secrets: inherit\n"), []lint.FindingArgs{SecretsInheritRemote{Uses: "octo/shared/.github/workflows/d.yml@v1"}}},
		{"local", callJob("./.github/workflows/d.yml", "    secrets: inherit\n"), []lint.FindingArgs{SecretsInheritLocal{Uses: "./.github/workflows/d.yml"}}},
		{"self", callJob("$/.github/workflows/d.yml", "    secrets: inherit\n"), []lint.FindingArgs{SecretsInheritLocal{Uses: "$/.github/workflows/d.yml"}}},
		{"mapping", callJob("octo/shared/.github/workflows/d.yml@v1", "    secrets:\n      token: ${{ secrets.TOKEN }}\n"), nil},
		{"none", callJob("./.github/workflows/d.yml", ""), nil},
		{"rejected uses", callJob("foo", "    secrets: inherit\n"), nil},
		{"folded", callJob("${{ './.github/workflows/d.yml' }}", "    secrets: inherit\n"), []lint.FindingArgs{SecretsInheritLocal{Uses: "${{ './.github/workflows/d.yml' }}"}}},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SecretsInherit}, wfFile(c.src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(c.want) {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		for i, w := range c.want {
			if f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i]; !argsEqual(f.Args, w) || f.Certainty != lint.CertaintyConfirmed {
				t.Errorf("%s: %+v %v, want %+v confirmed", c.name, f.Args, f.Certainty, w)
			}
		}
	}
}

// TestSecretsInheritRepo: the repository's own name in an
// owner/repo uses is local when --repo names it, in any case.
func TestSecretsInheritRepo(t *testing.T) {
	src := callJob("O/R/.github/workflows/d.yml@v1", "    secrets: inherit\n")
	for _, c := range []struct {
		repo string
		want lint.FindingArgs
	}{
		{"o/r", SecretsInheritLocal{Uses: "O/R/.github/workflows/d.yml@v1"}},
		{"o/other", SecretsInheritRemote{Uses: "O/R/.github/workflows/d.yml@v1"}},
		{"", SecretsInheritRemote{Uses: "O/R/.github/workflows/d.yml@v1"}},
	} {
		in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
		if err != nil {
			t.Fatal(err)
		}
		if c.repo != "" {
			in.Repo, _ = facts.ParseRepo(c.repo)
		}
		reg, err := lint.NewRegistry([]lint.Rule{SecretsInherit})
		if err != nil {
			t.Fatal(err)
		}
		rep := lint.Run(context.Background(), in, reg, worstCase(nil))
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || !argsEqual(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args, c.want) {
			t.Errorf("%q: %+v, want %+v", c.repo, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), c.want)
		}
	}
}

// TestSecretsInheritLocalReads: .local only when a job of the called
// workflow reads the secrets without naming them, with that read as related
// (the workflows of the runs observed for secret-exposure,
// testdata/observed/secret-exposure/5); and for a called workflow that is
// not among the inputs.
func TestSecretsInheritLocalReads(t *testing.T) {
	files := map[string]string{}
	for _, f := range []string{"s3-callers.yml", "called-tojson.yml", "called-plain.yml"} {
		b, err := os.ReadFile("testdata/observed/secret-exposure/5/.github/workflows/" + f)
		if err != nil {
			t.Fatal(err)
		}
		files[".github/workflows/"+f] = string(b)
	}
	rep, _, _ := checkRules(t, []lint.Rule{SecretsInherit}, files, exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if a := f.Args.(SecretsInheritLocal); a.Uses != "./.github/workflows/called-tojson.yml" || len(f.Related) != 1 || f.Related[0].Location.File.Input.String() != ".github/workflows/called-tojson.yml" {
		t.Errorf("%+v %+v", f.Args, f.Related)
	}
	rep, _, _ = checkRules(t, []lint.Rule{SecretsInherit}, wfFile(callJob("./.github/workflows/d.yml", "    secrets: inherit\n")), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Related) != 0 {
		t.Errorf("not among the inputs: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestSecretsInheritNestedUnknown fixes the nested form of the false
// positive named-reads, whose example is the direct form: the called
// workflow calls, in turn, a workflow that is not among the inputs.
func TestSecretsInheritNestedUnknown(t *testing.T) {
	files := map[string]string{
		".github/workflows/ci.yml":  callJob("./.github/workflows/mid.yml", "    secrets: inherit\n"),
		".github/workflows/mid.yml": "on:\n  workflow_call:\njobs:\n  m:\n    uses: ./.github/workflows/inner.yml\n    secrets: inherit\n",
	}
	rep, _, _ := checkRules(t, []lint.Rule{SecretsInherit}, files, exposureFacts{})
	var at []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if _, ok := f.Args.(SecretsInheritLocal); ok {
			at = append(at, f.Location.File.Input.String())
		}
	}
	slices.Sort(at)
	if !slices.Equal(at, []string{".github/workflows/ci.yml", ".github/workflows/mid.yml"}) {
		t.Errorf("%q", at)
	}
}
