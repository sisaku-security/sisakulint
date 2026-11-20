package taint

import (
	"os"
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/shell"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/internal/corpus"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// TestReadScriptTreeOnCorpus: for each run of the workflows of the
// corpus, the tree read with the places of its ${{ }} is the tree of
// shell.Parse (no difference was found in 870 scripts when the IR was
// made). One file in seven unless ACTIONS_CORPUS=full.
func TestReadScriptTreeOnCorpus(t *testing.T) {
	files := corpus.Files(t)
	n := 0
	for _, f := range files {
		if f.Kind != corpus.KindWorkflow {
			continue
		}
		src, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		w, _ := workflow.Parse(cst.ParseMode(src, cst.ModeGitHub))
		for _, s := range Analyze(w, nil).Sinks {
			if s.Kind != analysis.SinkRun {
				continue
			}
			n++
			if got, want := ReadScript(nil, s.Value).Script, shell.Parse(Masked(s.Value)); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: the trees of a run differ", f.Rel)
			}
		}
	}
	t.Logf("%d runs", n)
}

// TestAnalyzeWithAMemo: an analysis with a memo is the analysis without.
func TestAnalyzeWithAMemo(t *testing.T) {
	src := "on: issues\njobs:\n  b:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n          echo \"t=${{ github.event.issue.body }}\" >> \"$GITHUB_ENV\"\n"
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	if got, want := AnalyzeWith(w, nil, shell.NewMemo()), Analyze(w, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
