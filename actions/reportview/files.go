package reportview

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// File is an input that a node of the page is in, whole: the page draws
// the path of a finding over its lines.
type File struct {
	Input facts.InputPath `json:"input"`
	Lines []string        `json:"lines"` // without their line breaks; line N is Lines[N-1]
}

// filesOf are the inputs of in that a node of p is in, in the order of
// their paths. A file of a fact is not an input, and is not held.
func filesOf(p Page, in lint.Inputs) []File {
	seen := map[facts.InputPath]bool{}
	add := func(n Node) {
		if n.Input != nil {
			seen[*n.Input] = true
		}
	}
	for _, f := range p.Findings {
		for _, n := range f.Path {
			add(n)
		}
		for _, n := range f.Related {
			add(n)
		}
	}
	for _, f := range p.QualityFindings {
		for _, n := range f.Path {
			add(n)
		}
		for _, n := range f.Related {
			add(n)
		}
	}
	var names []facts.InputPath
	for n := range seen {
		names = append(names, n)
	}
	slices.SortFunc(names, facts.CompareInputPaths)
	out := []File{}
	for _, name := range names {
		input, st := in.Lookup(name)
		if st != lint.LookupFound || input.Tree == nil {
			continue
		}
		out = append(out, File{Input: name, Lines: linesOf(input.Tree.Bytes())})
	}
	return out
}

// filesOfInputs are every input of in, whole.
func filesOfInputs(in lint.Inputs) []File {
	out := []File{}
	for _, input := range in.List {
		if input.Tree != nil {
			out = append(out, File{Input: input.Name, Lines: linesOf(input.Tree.Bytes())})
		}
	}
	return out
}

// linesOf are the lines of src without their breaks; the break that ends
// the file starts no line.
func linesOf(src []byte) []string {
	starts := lineStarts(src)
	if len(starts) > 1 && starts[len(starts)-1] == len(src) {
		starts = starts[:len(starts)-1]
	}
	lines := make([]string, len(starts))
	for i := range starts {
		lines[i] = lineText(src, starts, i+1)
	}
	return lines
}
