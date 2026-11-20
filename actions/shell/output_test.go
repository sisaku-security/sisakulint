package shell

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// outputBodies reads s with an OutputReading as a reader of outputs does:
// a walk of the script that does not go into the words of a simple
// command, and a nested walk of each $( ) of them, from the reading of the
// command. It is the names of the functions whose bodies the walks give, in
// order, and the CallsNotRead.
func outputBodies(s string, limit int, reads int) ([]string, CallsNotRead) {
	sc := Parse(s)
	var nr CallsNotRead
	o := NewOutputReading(s, sc, NewNameVisibility(s, sc), &nr)
	if limit > 0 {
		o.limit = limit
	}
	var bodies []string
	var read func(cs []Command, from *DescriptorReading)
	read = func(cs []Command, from *DescriptorReading) {
		d := o.Begin(from, false)
		Walk(s, cs, Enclosing{}, Visitor{Descriptors: d, Command: func(c Command, at Enclosing) bool {
			if at.Call != nil && at.Func != nil && at.Func.Body == c {
				n, _ := literalOf(s, at.Func.Name)
				bodies = append(bodies, n)
			}
			x, ok := c.(*Simple)
			if !ok {
				return true
			}
			for _, w := range x.Words {
				for _, p := range w.Parts {
					if p.Sub != nil {
						read(p.Sub.List, d)
					}
				}
			}
			return false
		}})
		o.End(d)
	}
	for range max(reads, 1) {
		read(sc.List, nil)
	}
	return bodies, nr
}

func TestOutputReadingShares(t *testing.T) {
	// a nested reading does not read again a definition a reading around it
	// is reading: f calls itself through two $( )
	if got, _ := outputBodies("f() { echo \"$(g)\"; }\ng() { echo \"$(f)\"; }\nf\n", 0, 1); !slices.Equal(got, []string{"f", "g"}) {
		t.Errorf("recursion through nested readings: got %q", got)
	}
	// the limit of calls counts the outer reading and its nested readings
	// together: past the nested reading of f1, the outer reading does not
	// read the body of k
	var b strings.Builder
	for i := 1; i < 7; i++ {
		fmt.Fprintf(&b, "f%d() { f%[2]d; f%[2]d; f%[2]d; f%[2]d; }\n", i, i+1)
	}
	b.WriteString("f7() { :; }\nk() { :; }\nh() { echo \"$(f1)\"; k; }\nh\n")
	got, nr := outputBodies(b.String(), 0, 1)
	if slices.Contains(got, "k") || !nr.OK {
		t.Errorf("limit across nested readings: k read %v, not read %v", slices.Contains(got, "k"), nr)
	}
	// each outer reading counts from 0
	if got, _ := outputBodies("k() { :; }\nk\n", 0, 2); !slices.Equal(got, []string{"k", "k"}) {
		t.Errorf("each outer reading: got %q", got)
	}
	// the limit of the run: past it, no outer reading reads a body
	s := "f() { :; }\n" + strings.Repeat("f\n", 20)
	got, nr = outputBodies(s, 10, 2)
	if len(got) != 10 || !nr.OK {
		t.Errorf("limit of the run: %d bodies, not read %v", len(got), nr)
	}
}

func TestDescriptorReadingOutput(t *testing.T) {
	for _, c := range []struct {
		script string
		want   []string // the simple commands whose standard output goes to the output, but exec
	}{
		{"echo a; echo b >/dev/null; echo c >&2", []string{"echo a"}},
		{"exec >/dev/null; echo a", nil},
		{"exec 2>&1; echo a >&2", []string{"echo a >&2"}},
		{"exec >&-; echo a", nil},
		{"{ echo a >&3; } 3>&1 >/dev/null", []string{"echo a >&3"}},
		{"f() { return; echo a; }; f", []string{"f", "return"}},
		{"f() { exit; }; f; echo a", []string{"f", "exit"}},
		{"echo a >&4", nil},
		{"f() { echo a >&2; }; f |& cat", []string{"f", "echo a >&2", "cat"}},
		{"f() { echo a >&2; }; f 2>/dev/null", []string{"f 2>/dev/null"}},
	} {
		sc := Parse(c.script)
		o := NewOutputReading(c.script, sc, NewNameVisibility(c.script, sc), &CallsNotRead{})
		d := o.Begin(nil, false)
		var got []string
		Walk(c.script, sc.List, Enclosing{}, Visitor{Descriptors: d, Command: func(cmd Command, at Enclosing) bool {
			x, ok := cmd.(*Simple)
			if !ok {
				return true
			}
			if text := c.script[x.Span().Start:x.Span().End]; !strings.HasPrefix(text, "exec") && d.Output(x) {
				got = append(got, text)
			}
			return false
		}})
		o.End(d)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.script, got, c.want)
		}
	}
}

// outputCuts reads s as outputBodies does, with Count after each simple
// command, and is Cuts.
func outputCuts(s string) (int, int) {
	sc := Parse(s)
	o := NewOutputReading(s, sc, NewNameVisibility(s, sc), &CallsNotRead{})
	var read func(cs []Command, from *DescriptorReading)
	read = func(cs []Command, from *DescriptorReading) {
		d := o.Begin(from, false)
		Walk(s, cs, Enclosing{}, Visitor{Descriptors: d, Command: func(c Command, at Enclosing) bool {
			x, ok := c.(*Simple)
			if !ok {
				return true
			}
			for _, w := range x.Words {
				for _, p := range w.Parts {
					if p.Sub != nil {
						read(p.Sub.List, d)
					}
				}
			}
			o.Count(x)
			return false
		}})
		o.End(d)
	}
	read(sc.List, nil)
	return o.Cuts()
}

func TestOutputReadingCount(t *testing.T) {
	if all, rec := outputCuts("f() { echo \"$(f)\"; }\nf\n"); all != 1 || rec != 1 {
		t.Errorf("recursion: cuts %d, recursions %d", all, rec)
	}
	if all, rec := outputCuts("f() { :; }\nf\nf\n"); all != 0 || rec != 0 {
		t.Errorf("no cut: cuts %d, recursions %d", all, rec)
	}
	// a call past the limit, after a $( ) in its words that reached it
	var b strings.Builder
	for i := 1; i < 7; i++ {
		fmt.Fprintf(&b, "f%d() { f%[2]d; f%[2]d; f%[2]d; f%[2]d; }\n", i, i+1)
	}
	b.WriteString("f7() { :; }\nk() { :; }\nk \"$(f1)\"\n")
	if all, rec := outputCuts(b.String()); all < 1 || rec != 0 {
		t.Errorf("limit: cuts %d, recursions %d", all, rec)
	}
}

// endedAt is, for each simple command of s by its text, whether every path
// to it ended, read by a walk of descriptors with the definitions of s.
func endedAt(s string) map[string]bool {
	sc := Parse(s)
	o := NewOutputReading(s, sc, NewNameVisibility(s, sc), &CallsNotRead{})
	d := o.Begin(nil, false)
	out := map[string]bool{}
	Walk(s, sc.List, Enclosing{}, Visitor{Descriptors: d, Command: func(c Command, at Enclosing) bool {
		if x, ok := c.(*Simple); ok {
			out[s[x.Span().Start:x.Span().End]] = d.reading.ended
		}
		return true
	}})
	o.End(d)
	return out
}

// TestWalkSubstitutionJump: a break, continue or return in a $( ) ends the
// script of the $( ) where bash 5.3.15 takes it (2026-11-16).
func TestWalkSubstitutionJump(t *testing.T) {
	for _, c := range []struct {
		script, command string
		ended           bool
	}{
		{"f() { x=$(return; echo r); }; f", "echo r", true},
		{"for i in 1; do y=$(break; echo b); done", "echo b", true},
		{"for i in 1; do y=$(continue; echo c); done", "echo c", true},
		{"w=$(exit; echo e)", "echo e", true},
		{"for i in 1; do u=$(echo $(break; echo nn) m); done", "echo nn", true},
		{"for i in 1; do u=$(echo $(break; echo nn) m); done", "echo $(break; echo nn) m", false},
		{"x=$(return; echo r)", "echo r", false},
		{"y=$(break; echo b)", "echo b", false},
		{"for i in 1; do z=$( (break; echo n) ); done", "echo n", false},
		{"for i in 1; do f() { echo \"$(break; echo fb)\"; }; f; done", "echo fb", false},
		{"for i in 1; do y=$(break; echo b); echo after; done", "echo after", false},
		{"for i in 1; do y=$(for j in 1; do break 2; done; echo b2); done", "echo b2", true}, // past the loops of the $( )
	} {
		got, ok := endedAt(c.script)[c.command]
		if !ok || got != c.ended {
			t.Errorf("%s: %q ended %v (read %v), want %v", c.script, c.command, got, ok, c.ended)
		}
	}
}

// TestOutputReadingJump: a nested reading of a $( ) of a command in a loop
// ends at a break of its script.
func TestOutputReadingJump(t *testing.T) {
	s := "for i in 1; do echo \"$(break; echo b)\"; done\n"
	sc := Parse(s)
	o := NewOutputReading(s, sc, NewNameVisibility(s, sc), &CallsNotRead{})
	ended := map[string]bool{}
	var read func(cs []Command, from *DescriptorReading)
	read = func(cs []Command, from *DescriptorReading) {
		d := o.Begin(from, false)
		Walk(s, cs, Enclosing{}, Visitor{Descriptors: d, Command: func(c Command, at Enclosing) bool {
			x, ok := c.(*Simple)
			if !ok {
				return true
			}
			ended[s[x.Span().Start:x.Span().End]] = d.reading.ended
			for _, w := range x.Words {
				for _, p := range w.Parts {
					if p.Sub != nil {
						read(p.Sub.List, d)
					}
				}
			}
			return false
		}})
		o.End(d)
	}
	read(sc.List, nil)
	if !ended["echo b"] {
		t.Errorf("echo b after break in the $( ) of a command in a loop: not ended")
	}
}
