package expr

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// show writes a tree in a prefix form that names each node kind.
func show(n Node) string {
	switch n := n.(type) {
	case nil:
		return "nil"
	case *Literal:
		if n.Kind == LitString {
			return fmt.Sprintf("%q", n.Str)
		}
		return n.Raw
	case *Context:
		return n.Name
	case *Property:
		return show(n.X) + "." + n.Name
	case *Index:
		return show(n.X) + "[" + show(n.Index) + "]"
	case *Star:
		if n.Bracket {
			return show(n.X) + "[*]"
		}
		return show(n.X) + ".*"
	case *Call:
		var args []string
		for _, a := range n.Args {
			args = append(args, show(a))
		}
		return n.Name + "(" + strings.Join(args, ", ") + ")"
	case *Not:
		return "!" + show(n.X)
	case *Compare:
		return "(" + show(n.X) + " " + n.Op.String() + " " + show(n.Y) + ")"
	case *Logical:
		var xs []string
		for _, x := range n.Xs {
			xs = append(xs, show(x))
		}
		return "(" + strings.Join(xs, " "+n.Op.String()+" ") + ")"
	case *Group:
		return "{" + show(n.X) + "}"
	case *Wildcard:
		return "*"
	}
	return "?"
}

func TestParse(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a", "a"},
		{" a.b.c ", "a.b.c"},
		{"a['b'].c", `a["b"].c`},
		{"a.*.b", "a.*.b"},
		{"a[*].b", "a[*].b"},
		{"a[b[0]]", "a[b[0]]"},
		{"f()", "f()"},
		{"format('{0}', a, 1)", `format("{0}", a, 1)`},
		{"fromJSON(x).a[0]", "fromJSON(x).a[0]"},
		{"(a).b", "{a}.b"},
		{"a || b && c", "(a || (b && c))"},
		{"a && b || c", "((a && b) || c)"},
		{"a && b && c", "(a && b && c)"},
		{"a || b || c", "(a || b || c)"},
		{"a == b < c", "(a == (b < c))"},
		{"a < b == c", "((a < b) == c)"},
		{"a == b == c", "((a == b) == c)"},
		{"!a == b", "(!a == b)"},
		{"!(a == b)", "!{(a == b)}"},
		{"a != b", "(a != b)"},
		{"a >= 1 && b <= 2", "((a >= 1) && (b <= 2))"},
		{"null == false", "(null == false)"},
		{"'a''b'", `"a'b"`},
		// A wildcard inside an index is an operand.
		{"a[*.b]", "a[*.b]"},
		{"a[*[0]]", "a[*[0]]"},
		{"a[* == 1]", "a[(* == 1)]"},
		{"a[*]", "a[*]"},
	}
	for _, tt := range tests {
		n, errs := Parse(tt.in)
		if len(errs) > 0 {
			t.Errorf("Parse(%q) errors %v", tt.in, errs)
			continue
		}
		if got := show(n); got != tt.want {
			t.Errorf("Parse(%q) = %s, want %s", tt.in, got, tt.want)
		}
		checkSpans(t, tt.in, n)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in   string
		code ErrorCode
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"a ==", ErrUnexpectedEnd},
		{"(a", ErrUnexpectedEnd},
		{"f(a", ErrUnexpectedEnd},
		{"a[0", ErrUnexpectedEnd},
		{"!", ErrUnexpectedEnd},
		{"a.", ErrUnexpectedEnd},
		{"'x'.y", ErrUnexpected},
		{"a b", ErrUnexpected},
		{"()", ErrUnexpected},
		{"a[]", ErrUnexpected},
		{"f(a,)", ErrUnexpected},
	}
	for _, tt := range tests {
		n, errs := Parse(tt.in)
		if len(errs) != 1 || errs[0].Code != tt.code {
			t.Errorf("Parse(%q) = %s, %v; want one %v", tt.in, show(n), errs, tt.code)
			continue
		}
		if e := errs[0].Span; e.Start < 0 || e.End > len(tt.in) || e.Start > e.End {
			t.Errorf("Parse(%q) error span %v outside the input", tt.in, e)
		}
	}
}

// deep nests n levels of ! (each ! is one node; the innermost operand is a
// leaf), which is n+1 nodes deep.
func deep(n int) string { return strings.Repeat("!", n) + "a" }

func TestParseLimits(t *testing.T) {
	// ExpressionConstants.MaxDepth = 50: the root is depth 1, leaves count.
	if _, errs := Parse(strings.Repeat("(", 49) + deep(49) + strings.Repeat(")", 49)); len(errs) != 0 {
		t.Errorf("depth 50 (groups not counted): %v", errs)
	}
	if _, errs := Parse(deep(50)); len(errs) != 1 || errs[0].Code != ErrDepth {
		t.Errorf("depth 51: %v", errs)
	}
	// a.b is Index(a, 'b') in the runner: depth 2.
	if _, errs := Parse("a" + strings.Repeat(".b", 49)); len(errs) != 0 {
		t.Errorf("49 derefs (depth 50): %v", errs)
	}
	if _, errs := Parse("a" + strings.Repeat(".b", 50)); len(errs) != 1 || errs[0].Code != ErrDepth {
		t.Errorf("50 derefs (depth 51): %v", errs)
	}
	// && flattens, also through a group: 100 operands are depth 2.
	if _, errs := Parse("a" + strings.Repeat(" && (a && a)", 50)); len(errs) != 0 {
		t.Errorf("flattened &&: %v", errs)
	}
	// ExpressionConstants.MaxLength = 21000 UTF-16 code units.
	if _, errs := Parse("'" + strings.Repeat("x", 20998) + "'"); len(errs) != 0 {
		t.Errorf("length 21000: %v", errs)
	}
	if _, errs := Parse("'" + strings.Repeat("x", 20999) + "'"); len(errs) != 1 || errs[0].Code != ErrLength {
		t.Errorf("length 21001: %v", errs)
	}
	// The runner trims before it checks the length.
	if _, errs := Parse("  '" + strings.Repeat("x", 20998) + "'  "); len(errs) != 0 {
		t.Errorf("length 21000 with spaces around: %v", errs)
	}
	// é is one UTF-16 code unit but two bytes.
	if _, errs := Parse("'" + strings.Repeat("é", 20998) + "'"); len(errs) != 0 {
		t.Errorf("length 21000 in UTF-16: %v", errs)
	}
}

// checkSpans checks that every node's span lies in the input and contains
// its children's spans.
func checkSpans(t *testing.T, in string, n Node) {
	t.Helper()
	var walk func(n, parent Node)
	walk = func(n, parent Node) {
		if n == nil {
			return
		}
		s := n.Span()
		if s.Start < 0 || s.End > len(in) || s.Start >= s.End {
			t.Errorf("%q: span %v of %s is outside the input", in, s, show(n))
		}
		if parent != nil {
			if p := parent.Span(); s.Start < p.Start || s.End > p.End {
				t.Errorf("%q: span %v of %s is outside its parent %v", in, s, show(n), p)
			}
		}
		for _, c := range Children(n) {
			walk(c, n)
		}
	}
	walk(n, nil)
}

// Errors point at the token.
func TestParseErrorSpans(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"1(xyz", "("},
		{"a ]b", "]"},
		{"a ==   ", "=="},
		{"a == 1.2.3", "1.2.3"},
		{"'abc", "'abc"},
		{"a b", "b"},
	} {
		_, errs := Parse(tt.in)
		if len(errs) != 1 {
			t.Errorf("Parse(%q) errors %v", tt.in, errs)
			continue
		}
		if got := tt.in[errs[0].Span.Start:errs[0].Span.End]; got != tt.want {
			t.Errorf("Parse(%q) error at %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseSpans(t *testing.T) {
	in := "  github.event['issue'] .title == 'x'"
	n, errs := Parse(in)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	c := n.(*Compare)
	p := c.X.(*Property)
	if got := in[p.Span().Start:p.Span().End]; got != "github.event['issue'] .title" {
		t.Errorf("property span = %q", got)
	}
	if got := in[p.NameSpan.Start:p.NameSpan.End]; got != "title" {
		t.Errorf("name span = %q", got)
	}
	if got := in[c.Span().Start:c.Span().End]; got != strings.TrimSpace(in) {
		t.Errorf("compare span = %q", got)
	}
}

// TestChildren: the nodes under each kind, in the order they are written.
func TestChildren(t *testing.T) {
	for in, want := range map[string][]string{
		"a.b":         {"a"},
		"a[b]":        {"a", "b"},
		"a.*":         {"a"},
		"f(a, b)":     {"a", "b"},
		"!a":          {"a"},
		"a == b":      {"a", "b"},
		"a && b || c": {"a && b", "c"},
		"(a)":         {"a"},
		"'s'":         nil,
		"github":      nil,
	} {
		n, errs := Parse(in)
		if errs != nil {
			t.Fatalf("Parse(%q) errors %v", in, errs)
		}
		var got []string
		for _, c := range Children(n) {
			got = append(got, in[c.Span().Start:c.Span().End])
		}
		if !slices.Equal(got, want) {
			t.Errorf("Children(%q) = %q, want %q", in, got, want)
		}
	}
}
