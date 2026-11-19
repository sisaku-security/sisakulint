package lint

import (
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// Inputs are e as the inputs of a run: one input, or the whole repository
// of an example of several files.
func (e Example) Inputs() (Inputs, error) {
	if len(e.Others) == 0 {
		return Single(InputBytes{Name: e.Name, InputKind: e.InputKind, Bytes: []byte(e.Text)})
	}
	fsys := fstest.MapFS{e.Name.String(): {Data: []byte(e.Text)}}
	for _, o := range e.Others {
		fsys[o.Name.String()] = &fstest.MapFile{Data: []byte(o.Text)}
	}
	return Enumerate(fsys)
}

// resolver answers what e.Facts say, as a file of facts does (a
// git.commit-ref follows from a git.ref-commit), and nothing else.
func (e Example) resolver() (facts.Resolver, error) {
	b, err := facts.EncodeFile(e.Facts)
	if err != nil {
		return nil, err
	}
	return facts.LoadStore(b)
}
