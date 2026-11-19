package artifact

import (
	"os"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/internal/corpus"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// TestCorpus runs Analyze on the workflows and action.yml files of
// yaml/corpus (corpus.Files: one in seven unless ACTIONS_CORPUS=full): no
// panic.
func TestCorpus(t *testing.T) {
	files := corpus.Files(t)
	for _, f := range files {
		src, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		tree := cst.ParseMode(src, cst.ModeGitHub)
		switch f.Kind {
		case corpus.KindAction:
			a, _ := workflow.ParseActionMetadata(tree)
			Analyze(nil, a)
		case corpus.KindWorkflow:
			w, _ := workflow.Parse(tree)
			Analyze(w, nil)
		}
	}
	t.Logf("%d files", len(files))
}
