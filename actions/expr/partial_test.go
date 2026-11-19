package expr

import (
	"strings"
	"testing"
)

// known answers github.event_name and github.event.action, and nothing
// else; it counts what it is asked.
type known struct {
	event  string
	action *Value // nil: not known
	asked  int
}

func (k *known) lookup(p []PathElem) (Value, bool) {
	k.asked++
	names := make([]string, len(p))
	for i, e := range p {
		names[i] = strings.ToLower(e.Name)
	}
	switch strings.Join(names, ".") {
	case "github.event_name":
		return String(k.event), true
	case "github.event.action":
		if k.action != nil {
			return *k.action, true
		}
	}
	return Value{}, false
}

func partial(t *testing.T, src string, k *known) Truth {
	t.Helper()
	n, errs := Parse(src)
	if len(errs) > 0 {
		t.Fatalf("Parse(%q): %v", src, errs)
	}
	return Partial(n, k.lookup).Truthy()
}

func TestPartial(t *testing.T) {
	null := Null()
	for _, c := range []struct {
		src    string
		event  string
		action *Value
		want   Truth
	}{
		{"github.event_name == 'issues'", "issues", nil, TruthTrue},
		// string comparison ignores case, on the runner and on the server
		{"github.event_name == 'ISSUES'", "issues", nil, TruthTrue},
		{"github.event_name == 'push'", "issues", nil, TruthFalse},
		{"github.event_name != 'Push'", "push", nil, TruthFalse},
		{"github['event_name'] == 'issues'", "issues", nil, TruthTrue},
		{"(github.event_name == 'issues')", "issues", nil, TruthTrue},
		{"github.event.action == 'opened'", "issues", nil, TruthUnknown},
		{"github.actor == 'me'", "issues", nil, TruthUnknown},
		// Kleene's logic: one false operand of && is false, one true of || is true
		{"github.event_name == 'push' && github.actor == 'me'", "issues", nil, TruthFalse},
		{"github.actor == 'me' && github.event_name == 'push'", "issues", nil, TruthFalse},
		{"github.event_name == 'issues' && github.actor == 'me'", "issues", nil, TruthUnknown},
		{"github.event_name == 'issues' || github.actor == 'me'", "issues", nil, TruthTrue},
		{"github.actor == 'me' || github.event_name == 'push'", "issues", nil, TruthUnknown},
		{"!(github.event_name == 'push')", "issues", nil, TruthTrue},
		{"!github.actor", "issues", nil, TruthUnknown},
		{"contains(fromJSON('[\"issues\", \"issue_comment\"]'), github.event_name)", "issues", nil, TruthTrue},
		{"contains(fromJSON('[\"issues\", \"issue_comment\"]'), github.event_name)", "push", nil, TruthFalse},
		{"contains('PUSHED', github.event_name)", "push", nil, TruthTrue},
		{"startsWith(github.event_name, 'ISS')", "issues", nil, TruthTrue},
		{"startsWith('Push-x', github.event_name)", "push", nil, TruthTrue},
		{"endsWith(github.event_name, 'x')", "issues", nil, TruthFalse},
		{"format('{0}-x', github.event_name) == 'issues-x'", "issues", nil, TruthTrue},
		// the functions of a job's state are not known before it runs
		{"success() && github.event_name == 'issues'", "issues", nil, TruthUnknown},
		{"success() && github.event_name == 'push'", "issues", nil, TruthFalse},
		{"always()", "issues", nil, TruthUnknown},
		{"fromJSON(github.actor)", "issues", nil, TruthUnknown},
		// values of different types: a number and a numeric string, null and
		// the empty string
		{"1 == '1'", "push", nil, TruthTrue},
		{"github.event.action == ''", "push", &null, TruthTrue},
		// what was not seen on GitHub is not guessed
		{"'é' == 'É'", "push", nil, TruthUnknown},
		{"true == 1", "push", nil, TruthUnknown},
		{"1 < 2", "push", nil, TruthUnknown},
		{"'a'", "push", nil, TruthTrue},
		{"''", "push", nil, TruthFalse},
		{"0", "push", nil, TruthFalse},
		{"null", "push", nil, TruthFalse},
	} {
		if got := partial(t, c.src, &known{event: c.event, action: c.action}); got != c.want {
			t.Errorf("%s with event %s: %v, want %v", c.src, c.event, got, c.want)
		}
	}
}

// TestPartialLinear: each reference is looked up once, so the time is linear
// in the expression.
func TestPartialLinear(t *testing.T) {
	src := strings.Repeat("github.actor == 'x' || ", 500) + "github.event_name == 'push'"
	k := &known{event: "issues"}
	if got := partial(t, src, k); got != TruthUnknown {
		t.Errorf("got %v", got)
	}
	if k.asked != 501 {
		t.Errorf("looked up %d times, want 501", k.asked)
	}
}

// Nested operators are evaluated once each too: the depth is not in the
// exponent.
func TestPartialNestedLinear(t *testing.T) {
	src := "github.event_name == 'push'"
	for range 10 { // within the depth of 50 that Parse allows
		src = "github.actor == 'x' || (github.actor == 'y' && (" + src + "))"
	}
	k := &known{event: "issues"}
	if got := partial(t, src, k); got != TruthUnknown {
		t.Errorf("got %v", got)
	}
	if k.asked != 21 {
		t.Errorf("looked up %d times, want 21", k.asked)
	}
}

// odd is an Abstract for the tests: equal to "a" and "b" only maybe,
// contained in a string with an x, and holding "a" and "b" maybe.
type odd struct{}

func (odd) Truthy() Truth { return TruthTrue }
func (odd) Equal(o Value) Truth {
	if s, ok := o.Str(); ok && (s == "a" || s == "b") {
		return TruthUnknown
	}
	return TruthFalse
}
func (odd) Within(s string) Truth {
	if strings.Contains(s, "x") {
		return TruthUnknown
	}
	return TruthFalse
}
func (odd) Prefix(s string) Truth { return TruthFalse }
func (odd) Suffix(s string) Truth { return TruthTrue }

// Contains is maybe for what odd may equal ("a", "b") and the empty
// string, else false; StartsWith is false and EndsWith true.
func (odd) Contains(s string) Truth {
	if s == "" || s == "a" || s == "b" {
		return TruthUnknown
	}
	return TruthFalse
}
func (odd) StartsWith(s string) Truth { return TruthFalse }
func (odd) EndsWith(s string) Truth   { return TruthTrue }

func TestPartialAbstract(t *testing.T) {
	lookup := func(p []PathElem) (Value, bool) {
		if HasPrefix(p, "x") {
			return AbstractValue(odd{}), true
		}
		return Value{}, false
	}
	for _, c := range []struct {
		src  string
		want Truth
	}{
		{"x == 'c'", TruthFalse},
		{"x != 'c'", TruthTrue},
		{"x == 'a'", TruthUnknown},
		{"'c' == x", TruthFalse},
		{"contains('XYZ', x)", TruthUnknown},
		{"contains('abc', x)", TruthFalse},
		{"contains(fromJSON('[\"c\",\"d\"]'), x)", TruthFalse},
		{"contains(fromJSON('[\"a\",\"d\"]'), x)", TruthUnknown},
		{"startsWith('abc', x)", TruthFalse},
		{"endsWith('abc', x)", TruthTrue},
		{"contains(x, 'a')", TruthUnknown},
		{"contains(x, 'A')", TruthUnknown},
		{"contains(x, 'z')", TruthFalse},
		{"startsWith(x, 'a')", TruthFalse},
		{"endsWith(x, 'q')", TruthTrue},
		{"x", TruthTrue},
		{"!x", TruthFalse},
		{"x == 'c' || y", TruthUnknown},
		{"x == 'c' && y", TruthFalse},
	} {
		n, errs := Parse(c.src)
		if len(errs) > 0 {
			t.Fatal(c.src, errs)
		}
		if got := Partial(n, lookup).Truthy(); got != c.want {
			t.Errorf("%s: %v, want %v", c.src, got, c.want)
		}
	}
}

func TestPartialWith(t *testing.T) {
	n, _ := Parse("a == 'x' && b == 'x'")
	first := n.(*Logical).Xs[0]
	lookup := func(p []PathElem) (Value, bool) { return String("x"), true }
	if got := Partial(n, lookup).Truthy(); got != TruthTrue {
		t.Fatalf("without override: %v", got)
	}
	got := PartialWith(n, lookup, func(m Node) (Value, bool) {
		if m == first {
			return Bool(false), true
		}
		return Value{}, false
	}).Truthy()
	if got != TruthFalse {
		t.Errorf("override: %v", got)
	}
}
