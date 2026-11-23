package shell

import (
	"slices"
	"testing"
)

var fuzzSeeds = []string{"echo \"a $(b) 'c'\" <<EOF\nx\nEOF\n", "eval \"$'\\''\" `x` ${y:-z} # c", "cat <<-'A' <<B\n\tA\nB\n", "echo $(case x in a) b;; esac)", "[[ ( -n \"$a\" && $(b) -eq 1 ) || ! c =~ ^(d|e f)$ ]] > o", "echo ${a:-${b:-$(c)}} \"${x:-\"a b\"}\" ${T/a/b} ${x:0:1} ${!p*} ${a[$(i)]:=v} ${x:-$(a}", "echo `a \\`b \\$c\\` \\\\` \"`d \\\"e\\\"`\"", "x=$(( `a` + $(b) )); (( `c` )); `if`"}

// derefs are the words ws points to that are there.
func derefs(ws ...*Word) []Word {
	var out []Word
	for _, w := range ws {
		if w != nil {
			out = append(out, *w)
		}
	}
	return out
}

func FuzzContexts(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		at := make([]int, 0, len(s)+2)
		for i := 0; i <= len(s)+1; i++ {
			at = append(at, i)
		}
		got := Quotings(s, at)
		if len(got) != len(at) {
			t.Fatalf("%d contexts for %d places", len(got), len(at))
		}
		if got[len(got)-1] != QuotingUnknown {
			t.Errorf("the place past the end is %v", got[len(got)-1])
		}
	})
}

// FuzzParse: no panic; every span in the script, and inside its parent's.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sc := Parse(s)
		if sc.Stop < 0 || sc.Stop > len(s) {
			t.Fatalf("stop %d of %d", sc.Stop, len(s))
		}
		in := func(outer Span, what string, sp Span) {
			if sp.Start < outer.Start || sp.End > outer.End || sp.Start > sp.End {
				t.Fatalf("%s %v outside %v", what, sp, outer)
			}
		}
		var cmds func(outer Span, cs []Command)
		var partsIn func(outer Span, ps []Part)
		partsIn = func(outer Span, ps []Part) {
			for _, p := range ps {
				in(outer, "part", p.Span)
				switch {
				case p.Kind == PartSubst && p.Backquote:
					if p.Sub != nil {
						if p.Sub.Stop < p.Span.Start || p.Sub.Stop > p.Span.End {
							t.Fatalf("the Sub of ` ` stops at %d, outside %v", p.Sub.Stop, p.Span)
						}
						cmds(p.Span, p.Sub.List)
					}
				case p.Kind == PartSubst || p.Kind == PartProcIn || p.Kind == PartProcOut:
					if p.Sub == nil {
						t.Fatalf("a part %v with no Sub", p.Kind)
					}
					if !p.Sub.Complete && sc.Complete {
						t.Fatalf("a Sub not complete in a script that is")
					}
					if p.Sub.Stop < p.Span.Start || p.Sub.Stop > p.Span.End {
						t.Fatalf("a Sub that stops at %d, outside %v", p.Sub.Stop, p.Span)
					}
					cmds(p.Span, p.Sub.List)
				case p.Sub != nil:
					t.Fatalf("a part %v with a Sub", p.Kind)
				}
				if x := p.Param; x != nil {
					if p.Kind != PartParamOp {
						t.Fatalf("a part %v with a ParamExpansion", p.Kind)
					}
					for _, w := range append(slices.Clone(x.Words), derefs(x.Subscript, x.Offset, x.Length)...) {
						in(p.Span, "word of ${ }", w.Span)
						partsIn(w.Span, w.Parts)
					}
				}
			}
		}
		words := func(outer Span, ws []Word) {
			for _, w := range ws {
				in(outer, "word", w.Span)
				partsIn(w.Span, w.Parts)
			}
		}
		// a heredoc's body is on the lines after its command: only in the script
		redirs := func(outer Span, rs []Redirect) {
			for _, r := range rs {
				in(outer, "redirect", r.Span)
				words(r.Span, []Word{r.Target})
				if r.Heredoc != nil {
					in(Span{0, len(s)}, "body", r.Heredoc.Body)
					partsIn(r.Heredoc.Body, r.Heredoc.Parts)
				}
			}
		}
		cmds = func(outer Span, cs []Command) {
			for _, c := range cs {
				sp := c.Span()
				in(outer, "command", sp)
				switch c := c.(type) {
				case *Simple:
					words(sp, c.Assigns)
					words(sp, c.Words)
					redirs(sp, c.Redirects)
				case *Compound:
					cmds(sp, c.Body)
					redirs(sp, c.Redirects)
				case *FuncDef:
					cmds(sp, []Command{c.Body})
				case *Pipeline:
					cmds(sp, c.Commands)
				case *AndOr:
					cmds(sp, c.Commands)
				case *Asynchronous:
					cmds(sp, []Command{c.Command})
				}
			}
		}
		cmds(Span{0, len(s)}, sc.List)
	})
}

// FuzzWalk: Walk does not panic, gives each command and part inside the
// script, and calls Leave once for each command it gives.
func FuzzWalk(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add("a | b & c |& d; coproc n { e; } > \"$(f)\" <<X\n$(g)\nX\n")
	f.Fuzz(func(t *testing.T, s string) {
		depth := 0
		in := func(sp Span) {
			if sp.Start < 0 || sp.End > len(s) || sp.Start > sp.End {
				t.Fatalf("%q: %v outside", s, sp)
			}
		}
		Walk(s, Parse(s).List, Enclosing{}, Visitor{
			Command: func(c Command, at Enclosing) bool {
				in(c.Span())
				if at.Env == nil {
					t.Fatalf("%q: no environment", s)
				}
				if p, ok := c.(*Pipeline); ok {
					for i := range p.Commands {
						for _, src := range PipeSources(s, p, i) {
							if src.Element < 0 || src.Element >= i {
								t.Fatalf("%q: source %d of command %d", s, src.Element, i)
							}
						}
						readers, _ := PipeReaders(s, p.Commands[i])
						for _, r := range readers {
							in(r.Span())
						}
					}
				}
				depth++
				return true
			},
			Leave: func(Command, Enclosing) { depth-- },
			Part:  func(p *Part, _ Enclosing) { in(p.Span) },
		})
		if depth != 0 {
			t.Fatalf("%q: %d commands not left", s, depth)
		}
	})
}

// FuzzNameVisibility: NewNameVisibility does not panic, and what it
// answers is inside the script.
func FuzzNameVisibility(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add("f(){ local s; g; s=$1; return; }; g(){ s=x; f; }; while c; do s=a | f; done && f & ( unset -f f; f )")
	f.Fuzz(func(t *testing.T, s string) {
		sc := Parse(s)
		v := NewNameVisibility(s, sc)
		for i := 0; i <= len(s); i++ {
			for _, a := range v.Reaching(VarName{"s"}, Span{i, i}) {
				if a.At.Start < 0 || a.At.End > len(s) {
					t.Fatalf("%q: %v outside", s, a.At)
				}
			}
		}
	})
}

// FuzzWrites: Writes does not panic, and every span it gives is inside the
// script.
func FuzzWrites(f *testing.F) {
	for _, s := range []string{`echo "t=$T" >> "$OUT"`, "{ echo \"a<<EOF\"; echo \"$B\"; echo EOF; } >> $OUT", `printf '%s=%s\n' a "$T" >> "$OUT"`, "cat <<EOF >> $OUT\nk=$T\nEOF", `echo "a=$(echo "$A" | tr -d '\n')" | tee -a $OUT`, `f() { echo a > >(f >> "$OUT"); }; f`, "exec 3>> $OUT; g() { echo \"$A\" >&3; }; g x | f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sc := Parse(s)
		for _, w := range Writes(s, sc, WriteOptions{Target: isOut, Holes: holes(s)}) {
			for _, o := range w.Out {
				if o.Span.Start < 0 || o.Span.End > len(s) || o.Span.Start > o.Span.End {
					t.Fatalf("%q: %v outside", s, o.Span)
				}
			}
		}
		for _, p := range Params(sc.List) {
			if p.Span.End > len(s) {
				t.Fatalf("%q: %v outside", s, p.Span)
			}
		}
	})
}
