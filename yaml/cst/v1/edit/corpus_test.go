package edit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

const suiteRoot = "../../../yaml-test-suite/data-2022-01-17"

// inputs are the suite's and the corpus's inputs, by name: suite/ and
// the ID of a case of the suite, corpus/ and the path of a file in the
// corpus.
func inputs(t testing.TB) map[string][]byte {
	t.Helper()
	cs, err := suitetest.LoadCached(suiteRoot)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string][]byte{}
	for _, c := range cs {
		in["suite/"+c.ID] = c.In
	}
	root, seeds := suitetest.CorpusSeeds(t)
	for _, path := range seeds {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		in["corpus/"+filepath.ToSlash(rel)] = b
	}
	return in
}

// applyAll applies edits, dropping the edits Apply refuses until the rest
// is applied: the one an error names, or, when it names none, each that
// fails alone. It checks the inverse and returns how many were refused.
func applyAll(t *testing.T, name string, tr *cst.Tree, edits []Edit) (Result, int) {
	t.Helper()
	refused := 0
	for {
		res, err := Apply(tr, edits)
		if err == nil {
			back, err := Apply(res.Tree, res.Inverse)
			if err != nil || !bytes.Equal(back.Tree.Bytes(), tr.Bytes()) {
				t.Errorf("%s: the inverse does not give the input back: %v", name, err)
			}
			return res, refused
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("%s: %v", name, err)
		}
		if e.Edit >= 0 {
			edits = append(edits[:e.Edit:e.Edit], edits[e.Edit+1:]...)
			refused++
			continue
		}
		var kept []Edit
		for _, ed := range edits {
			if _, err := Apply(tr, []Edit{ed}); err == nil {
				kept = append(kept, ed)
			}
		}
		if len(kept) == len(edits) {
			// each is applied alone, not all together: give up the file
			return Result{}, refused + len(edits)
		}
		refused += len(edits) - len(kept)
		edits = kept
	}
}

// firstWord is the first run of lower-case letters in s.
func firstWord(s string) (int, int, bool) {
	i := 0
	for i < len(s) && (s[i] < 'a' || s[i] > 'z') {
		i++
	}
	j := i
	for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
		j++
	}
	return i, j, j > i
}

func TestCorpus(t *testing.T) {
	scalars, same, replaced, refusedByReplace, refusedByApply := 0, 0, 0, 0, 0
	for name, src := range inputs(t) {
		tr := cst.Parse(src)
		var sameEdits, wordEdits []Edit
		for n := range allScalars(tr) {
			scalars++
			v, _ := decode(n)
			old := v.String()
			if ed, err := Replace(v, 0, len(old), old); err == nil {
				sameEdits = append(sameEdits, ed)
			}
			if i, j, ok := firstWord(old); ok {
				ed, err := Replace(v, i, j, "zz")
				if err != nil {
					refusedByReplace++
					continue
				}
				wordEdits = append(wordEdits, ed)
			}
		}
		// Replacing every value by itself changes no byte.
		res, refused := applyAll(t, name, tr, sameEdits)
		if len(tr.Errors()) == 0 && refused > 0 {
			t.Errorf("%s: %d edits that change nothing were refused", name, refused)
		}
		if res.Tree != nil && !bytes.Equal(res.Tree.Bytes(), src) {
			t.Errorf("%s: replacing values by themselves changed the bytes", name)
		}
		same += len(sameEdits) - refused
		_, refused = applyAll(t, name, tr, wordEdits)
		replaced += len(wordEdits) - refused
		refusedByApply += refused
	}
	t.Logf("%d scalars; %d replaced by themselves; first word replaced in %d, refused by Replace %d, by Apply %d",
		scalars, same, replaced, refusedByReplace, refusedByApply)
}

// TestInputNames: the name of an input of the corpus is its path in the
// corpus, so that the sampling by the name's checksum (corpus_structure_test,
// editor_test) picks the same operations in every checkout.
func TestInputNames(t *testing.T) {
	n := 0
	for name := range inputs(t) {
		if strings.HasPrefix(name, "suite/") {
			continue
		}
		n++
		if filepath.IsAbs(name) || !strings.HasPrefix(name, "corpus/") {
			t.Errorf("the input %s is not named by its path in the corpus", name)
		}
	}
	if n == 0 {
		t.Skip("no corpus")
	}
}
