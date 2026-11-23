package agent

import (
	"fmt"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
)

// TestWords: quotes and a backslash as shell-quote's parse and string-argv
// read flags.
func TestWords(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`--model x --allowedTools "Bash,Read"`, []string{"--model", "x", "--allowedTools", "Bash,Read"}},
		{"--a\n  --b 'c d'", []string{"--a", "--b", "c d"}},
		{`--x="a b" \-\-y`, []string{"--x=a b", "--y"}},
		{"", nil},
	} {
		if got := words(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStripComments: a line whose first non-blank is # is gone, as
// claude-code-action's stripShellComments drops it.
func TestStripComments(t *testing.T) {
	if got := stripComments("--a\n  # --dangerously-skip-permissions\n--b"); got != "--a\n--b" {
		t.Errorf("%q", got)
	}
}

// TestScanAt: each byte of a word comes from where it is in the value,
// past the quotes and the lines of comments the action drops.
func TestScanAt(t *testing.T) {
	v := "--a \"x y\"\n# c\n--b 'z'"
	s, of := stripCommentsAt(v)
	if s != stripComments(v) {
		t.Fatalf("stripped %q, want %q", s, stripComments(v))
	}
	ws := scan(s, of, nil)
	var got []string
	for _, w := range ws {
		got = append(got, fmt.Sprintf("%s@%d-%d", w.text, w.at[0], w.at[len(w.at)-1]+1))
	}
	want := []string{"--a@0-3", "x y@5-8", "--b@14-17", "z@19-20"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRecordAccumulates: an accumulating flag keeps its values, and adds
// those of the same flag later, as the action does; another
// flag still takes its last value.
func TestRecordAccumulates(t *testing.T) {
	ws := scan(`--allowedTools "Bash(gh:*),Read" Edit --permission-mode acceptEdits --allowedTools Write --permission-mode bypassPermissions`, nil, nil)
	r := record(ws)
	var vals []string
	for _, f := range r {
		if f.key == "allowedTools" {
			for _, i := range f.words[1:] {
				vals = append(vals, ws[i].text)
			}
		}
	}
	if !slices.Equal(vals, []string{"Bash(gh:*),Read", "Edit", "Write"}) {
		t.Errorf("allowedTools: %v", vals)
	}
	if m, _ := lastValue(r, "permission-mode"); m != "bypassPermissions" {
		t.Errorf("permission-mode: %q", m)
	}
}

// TestElements: the elements of a word split at commas, trimmed, with their
// spans in the value.
func TestElements(t *testing.T) {
	ws := scan(`--allowedTools "Bash(gh issue edit:*), Read"`, nil, nil)
	var got []string
	for _, e := range ws[1].elements(0, true, nil) {
		got = append(got, fmt.Sprintf("%s@%d-%d", e.text, e.span.Start, e.span.End))
	}
	if !slices.Equal(got, []string{"Bash(gh issue edit:*)@16-37", "Read@39-43"}) {
		t.Errorf("got %v", got)
	}
}

// TestScanOpaque: a ${{ }} stays in one word whatever blanks it has.
func TestScanOpaque(t *testing.T) {
	v := "--model ${{ vars.M }} --x"
	ws := scan(v, nil, []expr.Span{{Start: 8, End: 21}})
	var got []string
	for _, w := range ws {
		got = append(got, w.text)
	}
	if !slices.Equal(got, []string{"--model", "${{ vars.M }}", "--x"}) {
		t.Errorf("got %q", got)
	}
}
