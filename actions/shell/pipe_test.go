package shell

import (
	"fmt"
	"slices"
	"testing"
)

// lastPipeline is the last pipeline of script, at the top or in a list of
// an and-or list.
func lastPipeline(t *testing.T, script string) *Pipeline {
	t.Helper()
	var p *Pipeline
	Walk(script, Parse(script).List, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		if x, ok := c.(*Pipeline); ok && at.Env.Kind == ExecutionEnvironmentTop {
			p = x
		}
		return true
	}})
	if p == nil {
		t.Fatalf("%q: no pipeline", script)
	}
	return p
}

func TestPipeSources(t *testing.T) {
	v, c, u := PipePassageVerbatim, PipePassageChanged, PipePassageUnknown
	for _, tc := range []struct {
		script string
		want   []PipeSource // what reaches the last command
	}{
		{"echo x | bash", []PipeSource{{0, v}}},
		{"echo x | cat | bash", []PipeSource{{1, v}, {0, v}}},
		{"echo x > f | bash", nil},
		{"echo x > /dev/stdout | bash", []PipeSource{{0, v}}},
		{"echo x >&1 | bash", []PipeSource{{0, v}}},
		{"{ echo x >&2; } 2>&1 | bash", []PipeSource{{0, v}}},
		{"echo x >&2 |& bash", nil},
		{"{ echo x >&2; } 2>/dev/null |& bash", []PipeSource{{0, v}}},
		{"exec 3>&1; echo x >&3 | bash", nil},
		{"echo x | bash < /dev/null", []PipeSource{{0, v}}}, // what bash reads: PipeReaders
		{"echo x | bash <<EOF\na\nEOF", []PipeSource{{0, v}}},
		{"echo x | bash 0<&0", []PipeSource{{0, v}}},
		{"echo x | cat f | bash", []PipeSource{{1, v}}},
		{"echo x | cat - | bash", []PipeSource{{1, v}, {0, u}}},
		{"echo x | cat g - | bash", []PipeSource{{1, v}, {0, u}}},
		{"echo x | cat /dev/stdin | bash", []PipeSource{{1, v}, {0, u}}},
		{"echo x | tee f | bash", []PipeSource{{1, v}, {0, v}}},
		{"echo x | cat -n | bash", []PipeSource{{1, v}, {0, u}}}, // cat writes its input as it is only with no word (logwrite)
		{"echo x | sha256sum | bash", []PipeSource{{1, v}}},
		{"echo x | tr a b | bash", []PipeSource{{1, v}, {0, c}}},
		{"echo x | foo | bash", []PipeSource{{1, v}, {0, u}}},
		{"echo x | tr a b | foo | bash", []PipeSource{{2, v}, {1, u}, {0, u}}},
		{"echo x | coproc c { cat; } | bash", nil},
		{"coproc c { a; } |& b", nil},
		{"echo x | coproc c { cat; } | cat | bash", []PipeSource{{2, v}}},
		{"! echo x | bash", []PipeSource{{0, v}}},
		{"time echo x | bash", []PipeSource{{0, v}}},
		{"echo x | bash", []PipeSource{{0, v}}},
	} {
		p := lastPipeline(t, tc.script)
		got := PipeSources(tc.script, p, len(p.Commands)-1)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: %v, want %v", tc.script, got, tc.want)
		}
	}
}

// TestPipeSourcesMiddle: what reaches a command in the middle.
func TestPipeSourcesMiddle(t *testing.T) {
	script := "echo x | cat | bash | cat"
	p := lastPipeline(t, script)
	if got, want := fmt.Sprint(PipeSources(script, p, 2)), fmt.Sprint([]PipeSource{{1, PipePassageVerbatim}, {0, PipePassageVerbatim}}); got != want {
		t.Errorf("%v, want %v", got, want)
	}
	if got := PipeSources(script, p, 0); got != nil {
		t.Errorf("the first command: %v", got)
	}
}

func TestPipeReaders(t *testing.T) {
	for _, tc := range []struct {
		element string
		want    []string // the texts of the readers, in order
	}{
		{"bash", []string{"bash"}},
		{"bash < /dev/null", nil},
		{"bash 0<&0", []string{"bash 0<&0"}},
		{"{ bash; }", []string{"bash"}},
		{"{ bash; } < f", nil},
		{"{ a < f; bash; }", []string{"bash"}},
		{"( b | c )", []string{"b"}},
		{"coproc { bash; }", nil},
		{"{ echo hi; }", []string{"echo hi"}},
		{"y=$(bash)", []string{"bash"}},
		{"echo $(bash) < /dev/null", []string{"bash"}},
		{"cat <(bash)", []string{"cat <(bash)", "bash"}},
		{"{ x=$(bash); } < /dev/null", nil},
		{"while read l; do bash; done", []string{"read l", "bash"}},
		{"cat < /dev/null > \"$(bash)\"", nil}, // the target is expanded after the redirect before it
		{"cat > \"$(bash)\" < /dev/null", []string{"bash"}},
		{"{ exec 3<&0; bash <&3; }", []string{"bash <&3"}}, // an exec with no command reads nothing
		// $(( )) and ` ` are read as $( ) is (the owner's decision of 2026-11-15)
		{"echo $((1))", []string{"echo $((1))"}},
		{"echo `date`", []string{"echo `date`", "date"}},
		{"x=`bash`", []string{"bash"}},
		{"echo $(( $(bash) ))", []string{"echo $(( $(bash) ))", "bash"}},
	} {
		script := "echo x | " + tc.element
		p := lastPipeline(t, script)
		var got []string
		readers, unread := PipeReaders(script, p.Commands[len(p.Commands)-1])
		for _, s := range readers {
			got = append(got, script[s.Span().Start:s.Span().End])
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.want) || unread {
			t.Errorf("%q: %q (unread %v), want %q", tc.element, got, unread, tc.want)
		}
	}
}

// TestPipeReadersUnread: an element with places the tree does not read,
// or whose reading depends on what runs, may read the pipe.
func TestPipeReadersUnread(t *testing.T) {
	for _, element := range []string{
		"for i in $(bash); do :; done",
		"select i in $(bash); do :; done",
		"case $(bash) in a) :;; esac",
		"(( $(bash) ))",
		"{ f(){ bash; }; f; }",
	} {
		script := "echo x | { " + element + "; }"
		p := lastPipeline(t, script)
		if _, unread := PipeReaders(script, p.Commands[len(p.Commands)-1]); !unread {
			t.Errorf("%q: read whole", element)
		}
	}
}

// TestPipeReadersPaths: an exec that points the standard input elsewhere on
// some paths leaves the pipe on the others, where a command after it reads
// it.
func TestPipeReadersPaths(t *testing.T) {
	for _, tc := range []struct {
		element string
		want    []string
	}{
		{"{ a && exec 0</dev/null; bash; }", []string{"a", "bash"}},
		{"{ if a; then exec 0</dev/null; fi; bash; }", []string{"a", "bash"}},
		{"{ exec 0</dev/null; bash; }", nil},
		{"{ exec 0</dev/null || exec 0<&-; bash; }", nil},
		{"{ b | bash; }", []string{"b"}},
		{"{ shopt -s lastpipe; b | bash; }", []string{"shopt -s lastpipe", "b"}},
		// a file that names the standard input
		{"cat < /dev/stdin", []string{"cat < /dev/stdin"}},
		{"cat 0</dev/fd/0", []string{"cat 0</dev/fd/0"}},
		{"{ exec 3<&0; cat </dev/fd/3; }", []string{"cat </dev/fd/3"}},
		{"cat <> /dev/stdin", []string{"cat <> /dev/stdin"}},
		// the target of a compound's redirect is expanded after the redirects
		// before it
		{"{ :; } 2>\"$(cat)\" </dev/null", []string{"cat"}},
		{"( : ) 2>\"$(cat)\" </dev/null", []string{"cat"}},
		// a reading with no NameVisibility reads {name}>&-
		{"{ exec {fd}>&-; cat; }", []string{"cat"}},
	} {
		script := "echo x | " + tc.element
		p := lastPipeline(t, script)
		readers, unread := PipeReaders(script, p.Commands[len(p.Commands)-1])
		var got []string
		for _, r := range readers {
			got = append(got, script[r.Span().Start:r.Span().End])
		}
		if !slices.Equal(got, tc.want) || unread {
			t.Errorf("%q: readers %q, unread %v; want %q, false", tc.element, got, unread, tc.want)
		}
	}
}
