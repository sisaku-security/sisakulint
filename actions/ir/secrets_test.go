package ir

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestSecretsContextRead: a read of the secrets context, where it is, and
// the callers of a workflow that only a caller runs.
func TestSecretsContextRead(t *testing.T) {
	got := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - env:\n          X: ${{ toJSON(secrets) }}\n        run: \"true\"\n").allSecretsContextReads()
	if len(got) != 1 || got[0].text != "secrets" || got[0].calledOnly {
		t.Fatalf("%+v", got)
	}
}

// TestSecretsContextReadCallers: the callers of a called
// workflow decide it, through the call graph.
func TestSecretsContextReadCallers(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  c:\n    runs-on: x\n    steps:\n      - env:\n          X: ${{ toJSON(secrets) }}\n        run: \"true\"\n"
	for _, c := range []struct {
		name, caller string
		cov          analysis.CallerCoverage
		inherit      []string
	}{
		{"none", "", analysis.CallerCoverageNone, nil},
		{"named", "on: push\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n    secrets:\n      A: ${{ secrets.A }}\n", analysis.CallerCoverageAll, nil},
		{"inherit", "on: push\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n", analysis.CallerCoverageAll, []string{"a"}},
	} {
		files := [][2]string{{".github/workflows/called.yml", called}}
		if c.caller != "" {
			files = append(files, [2]string{".github/workflows/ci.yml", c.caller})
		}
		got := calledIR(t, files...).allSecretsContextReads()
		if len(got) != 1 || !got[0].calledOnly || got[0].callerCoverage != c.cov {
			t.Fatalf("%s: %+v", c.name, got)
		}
		var jobs []string
		for _, ic := range got[0].inheritCallers {
			jobs = append(jobs, ic.Job)
			if ic.Caller != calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")) || ic.At.InputName() != ".github/workflows/ci.yml" {
				t.Errorf("%s: caller at %s", c.name, ic.At.InputName())
			}
		}
		if !slices.Equal(jobs, c.inherit) {
			t.Errorf("%s: %q", c.name, jobs)
		}
	}
}

// TestSecretPart: a value taken out of a secret, with the secrets' names.
func TestSecretPart(t *testing.T) {
	got := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{ fromJSON(secrets.J).user }}\n").allSecretParts()
	if len(got) != 1 || !slices.Equal(got[0].secrets, []string{"J"}) || got[0].text != "${{ fromJSON(secrets.J).user }}" {
		t.Fatalf("%+v", got)
	}
}

// TestSecretsContextReadCallersUpstream: an inherit caller whose workflow is
// only called counts when a caller of it may give it every secret; a caller
// that passes named secrets gives only those.
func TestSecretsContextReadCallersUpstream(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  c:\n    runs-on: x\n    steps:\n      - env:\n          X: ${{ toJSON(secrets) }}\n        run: \"true\"\n"
	mid := "on:\n  workflow_call:\njobs:\n  m:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"
	top := func(secrets string) string {
		return "on: issues\njobs:\n  t:\n    uses: ./.github/workflows/mid.yml\n    secrets:" + secrets
	}
	for _, c := range []struct {
		name  string
		files [][2]string
		want  int
	}{
		{"named above", [][2]string{{".github/workflows/top.yml", top(" {A: '${{ secrets.A }}'}\n")}}, 0},
		{"inherit above", [][2]string{{".github/workflows/top.yml", top(" inherit\n")}}, 1},
		{"nameless value above", [][2]string{{".github/workflows/top.yml", top(" {ALL: '${{ toJSON(secrets) }}'}\n")}}, 1},
		{"no caller above", nil, 1}, // CallerCoverageNone: as for a called workflow with no caller among the inputs
		{"loop", [][2]string{{".github/workflows/top.yml", "on:\n  workflow_call:\njobs:\n  t:\n    uses: ./.github/workflows/mid.yml\n    secrets: inherit\n  u:\n    uses: ./.github/workflows/top.yml\n    secrets: inherit\n"}}, 0},
	} {
		files := append([][2]string{{".github/workflows/called.yml", called}, {".github/workflows/mid.yml", mid}}, c.files...)
		got := calledIR(t, files...).allSecretsContextReads()
		if len(got) != 1 || len(got[0].inheritCallers) != c.want {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	// the callers of mid.yml are not all among the inputs: as before
	got := calledIRPartial(t, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/mid.yml", mid}).allSecretsContextReads()
	if len(got) != 1 || len(got[0].inheritCallers) != 1 {
		t.Errorf("partial: %+v", got)
	}
}
