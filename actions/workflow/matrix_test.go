package workflow

import (
	"strings"
	"testing"
)

// TestMatrixVariables: the values a matrix gives each name, from its variables
// and include, and whether they are all written out.
func TestMatrixVariables(t *testing.T) {
	for _, c := range []struct{ name, matrix, want string }{
		{"vector", "{os: [ubuntu-latest, self-hosted]}", "os=ubuntu-latest,self-hosted"},
		{"include", "{os: [a], include: [{os: b}, {extra: c}]}", "os=a,b extra=c"},
		{"include only", "{include: [{os: self-hosted}]}", "os=self-hosted"},
		{"exclude", "{os: [a, b], exclude: [{os: b}]}", "os=a,b"},
		{"case", "{OS: [a], include: [{os: b}]}", "OS=a,b"},
		{"expr item", "{os: [a, '${{ inputs.x }}']}", "os=a,${{ inputs.x }}"},
		{"mapping item", "{os: [{x: 1}]}", "os=?"},
		{"vector expr", "{os: '${{ fromJSON(inputs.o) }}'}", "os=?"},
		{"include expr", "{os: [a], include: '${{ fromJSON(inputs.i) }}'}", "os=?a"},
		{"include entry expr", "{os: [a], include: ['${{ inputs.e }}']}", "os=?a"},
		{"matrix expr", "'${{ fromJSON(inputs.m) }}'", ""},
	} {
		w, _, _ := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix: "+c.matrix+"\n    steps:\n      - run: echo\n")
		j := w.Jobs.Value.Entries[0].Value.Value
		var got []string
		for _, v := range j.MatrixVariables {
			s := v.Name + "="
			if !v.Known {
				s += "?"
			}
			var vals []string
			for _, x := range v.Values {
				vals = append(vals, x.Text())
			}
			got = append(got, s+strings.Join(vals, ","))
		}
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("%s: %q, want %q", c.name, g, c.want)
		}
	}
}

// TestMatrixDiagnostics: the entries of
// include and of exclude are read alike, each a mapping.
func TestMatrixDiagnostics(t *testing.T) {
	for _, m := range []string{"{os: [a], include: [~]}", "{os: [a], exclude: [~]}"} {
		_, diags, _ := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix: "+m+"\n    steps:\n      - run: echo\n")
		if got := codes(diags); len(got) != 1 || got[0] != WrongKind {
			t.Errorf("%s: %v", m, got)
		}
	}
}
