package cst

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

var corpusReport = flag.String("corpus.report", "", "write the corpus files that have errors (path, code, line:col, message) to this file")

// TestCorpus parses every file of yaml/corpus. The invariants must hold for
// all of them; files with errors are only counted, since the corpus has no
// expected results (yaml/corpus/README.md).
func TestCorpus(t *testing.T) {
	var report strings.Builder
	root := suitetest.CorpusRoot(t)
	files := corpusFiles(t)
	withErrors := 0
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tr := Parse(src)
		if err := validate(tr); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if errs := tr.Errors(); len(errs) > 0 {
			withErrors++
			e := errs[0]
			pos := tr.Position(e.Span.Start)
			fmt.Fprintf(&report, "%s\t%d\t%d:%d\t%s\n", strings.TrimPrefix(path, root+"/"), e.Code, pos.Line, pos.Column, e.Msg)
		}
	}
	t.Logf("%d files, %d with errors", len(files), withErrors)
	if *corpusReport != "" {
		if err := os.WriteFile(*corpusReport, []byte(report.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
