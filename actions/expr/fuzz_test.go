package expr

import "testing"

var fuzzSeeds = []string{
	"", "${{ a }}", "x ${{ '}}' }} y", "${{", "${{ ' }}", "a.b['c'].*",
	"format('{0}', a, 1) == 'x' && !b || c[*].d", "0x1F <= .5", "(((a)))",
	"'a''b'", "f(a,)", "é ${{ é }}",
}

func FuzzScan(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		segs, errs := Scan(s)
		checkCover(t, s, segs)
		for _, e := range errs {
			if e.Span.Start < 0 || e.Span.End > len(s) || e.Span.Start > e.Span.End {
				t.Errorf("error span %v outside the input", e.Span)
			}
		}
	})
}

// FuzzFoldName: two names are equal by EqualName exactly when their
// FoldNames are, so a map keyed by FoldName finds what EqualName would.
func FuzzFoldName(f *testing.F) {
	for _, s := range []string{"", "FOO", "\xc4\xb0X", "\xe2\x84\xaaX", "\xff", "\xe2\x82A", "\xef\xbf\xbd"} {
		f.Add(s, "foo")
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if eq, fold := EqualName(a, b), FoldName(a) == FoldName(b); eq != fold {
			t.Fatalf("EqualName(%q, %q) = %v, but FoldName gives %q and %q", a, b, eq, FoldName(a), FoldName(b))
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, errs := Parse(s)
		if (n == nil) == (len(errs) == 0) {
			t.Fatalf("Parse(%q) = %v, %v: want a node or an error", s, n, errs)
		}
		for _, e := range errs {
			if e.Span.Start < 0 || e.Span.End > len(s) || e.Span.Start > e.Span.End {
				t.Errorf("error span %v outside the input", e.Span)
			}
		}
		checkSpans(t, s, n)
		AccessPath(n)
	})
}
