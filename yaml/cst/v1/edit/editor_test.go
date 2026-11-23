package edit

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"os"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// An Editor that has made other edits of a tree makes the same edit as a
// new one: what it remembers is what a new one would find. One Editor
// makes every structural operation on every input, errors included, in
// both modes; a new one makes every sampled-th (as TestCorpusStructure),
// and all of them with EDIT_CORPUS=full.
func TestEditorRemembers(t *testing.T) {
	if testing.Short() {
		t.Skip("the structural operations on the corpus take a while")
	}
	every := sampled
	if os.Getenv("EDIT_CORPUS") == "full" {
		every = 1
	}
	for name, src := range inputs(t) {
		offset := int(crc32.ChecksumIEEE([]byte(name)) % uint32(every))
		for _, mode := range []cst.Mode{cst.ModeSpec, cst.ModeGitHub} {
			tr := cst.ParseMode(src, mode)
			shared := structuralOps(tr, sharedEditor())
			fresh := structuralOps(tr, func() *Editor { return new(Editor) })
			for k := range shared {
				a, errA := shared[k].make()
				if k%every != offset {
					continue
				}
				b, errB := fresh[k].make()
				if fmt.Sprint(errA) != fmt.Sprint(errB) || a.Span != b.Span || !bytes.Equal(a.Old, b.Old) || !bytes.Equal(a.New, b.New) {
					t.Errorf("%s (mode %d): %s %d: shared %v %q %v, new %v %q %v", name, mode, shared[k].name, k, a.Span, a.New, errA, b.Span, b.New, errB)
				}
			}
		}
	}
}
