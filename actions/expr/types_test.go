package expr

import (
	"slices"
	"strings"
	"testing"
)

// typesOf answers the references of names, by their path in lowercase
// joined by dots, with the types given.
func typesOf(names map[string]Type) func([]PathElem) (Type, bool) {
	return func(p []PathElem) (Type, bool) {
		parts := make([]string, len(p))
		for i, e := range p {
			if e.Name == "" {
				return Type{}, false
			}
			parts[i] = strings.ToLower(e.Name)
		}
		t, ok := names[strings.Join(parts, ".")]
		return t, ok
	}
}

func mustParse(t *testing.T, src string) Node {
	t.Helper()
	n, errs := Parse(src)
	if len(errs) > 0 {
		t.Fatalf("Parse(%q): %v", src, errs)
	}
	return n
}

func TestTypeOfExpr(t *testing.T) {
	boolean, str := TypeOf(ValueBoolean), TypeOf(ValueString)
	refs := typesOf(map[string]Type{"c": boolean, "t": str, "a": boolean, "github.event": TypeOf(ValueObject)})
	tests := []struct {
		src  string
		want []ValueType // nil: not known
	}{
		{"'a'", []ValueType{ValueString}},
		{"format('{0}', x)", []ValueType{ValueString}},
		{"toJSON(x)", []ValueType{ValueString}},
		{"join(x)", []ValueType{ValueString}},
		{"hashFiles('a')", []ValueType{ValueString}},
		{"1 == 2", []ValueType{ValueBoolean}},
		{"!x", []ValueType{ValueBoolean}},
		{"contains(a, b)", []ValueType{ValueBoolean}},
		{"always()", []ValueType{ValueBoolean}},
		{"1", []ValueType{ValueNumber}},
		{"null", []ValueType{ValueNull}},
		{"github.event.commits.*.id", []ValueType{ValueArray}},
		{"x.*", []ValueType{ValueArray}},
		{"github.event", []ValueType{ValueObject}},
		{"fromJSON('[\"a\"]')", []ValueType{ValueArray}},
		{"fromJSON('{\"a\":1}')", []ValueType{ValueObject}},
		{"fromJSON('true')", []ValueType{ValueBoolean}},
		{"fromJSON(x)", nil},
		{"fromJSON('{')", nil},
		{"c && 'x' || 'y'", []ValueType{ValueString}},
		{"c && 1 || 0", []ValueType{ValueNumber}},
		{"t || 30", []ValueType{ValueNumber, ValueString}},
		{"case(a, 'x', 1)", []ValueType{ValueNumber, ValueString}},
		{"(c)", []ValueType{ValueBoolean}},
		{"github.sha", nil},
		{"c && x", nil},
		{"0x10 || 'x'", []ValueType{ValueNumber, ValueString}},
	}
	for _, tt := range tests {
		got := TypeOfExpr(mustParse(t, tt.src), refs)
		if tt.want == nil {
			if got.Known() {
				t.Errorf("TypeOfExpr(%q) = %v, want not known", tt.src, got.ValueTypes())
			}
			continue
		}
		if !got.Known() || !slices.Equal(got.ValueTypes(), tt.want) {
			t.Errorf("TypeOfExpr(%q) = %v (known %v), want %v", tt.src, got.ValueTypes(), got.Known(), tt.want)
		}
	}
}

func TestTypeOnly(t *testing.T) {
	ts := TypeOfExpr(mustParse(t, "t || 30"), typesOf(map[string]Type{"t": TypeOf(ValueString)}))
	if ts.Only(ValueNumber) || ts.Only(ValueString) || !ts.Only(ValueString, ValueNumber) {
		t.Errorf("Only of string or number: %v", ts.ValueTypes())
	}
	if AnyType().Only(ValueString, ValueNumber, ValueBoolean, ValueNull, ValueObject, ValueArray) != true {
		t.Error("AnyType is every type")
	}
}

func TestCallMistakes(t *testing.T) {
	refs := typesOf(map[string]Type{"github.event": TypeOf(ValueObject), "b": AnyType(), "s": TypeOf(ValueString), "f": TypeOf(ValueBoolean), "m": TypeOf(ValueBoolean).Union(TypeOf(ValueString))})
	tests := []struct {
		src  string
		want []CallMistakeKind
		arg  string // the source of Arg of the first, when it has one
	}{
		{"format('{0} {1}', 'a')", []CallMistakeKind{MistakeFormatArguments}, ""},
		{"format('{0}', 'a', 'b')", nil, ""},
		{"format('{{0}} {0}', 'a')", nil, ""},
		{"format('{1:x}', 'a')", []CallMistakeKind{MistakeFormatArguments}, ""},
		// the runner reads the number by Byte.TryParse: zeros first are one number, and 256 is no number
		{"format('{0001}', 'a')", []CallMistakeKind{MistakeFormatArguments}, ""},
		{"format('{0001}', 'a', 'b')", nil, ""},
		{"format('{256}', 'a')", nil, ""},
		{"format(s, 'a')", nil, ""},
		{"case('x', 'a', 'b')", []CallMistakeKind{MistakeCasePredicate}, "'x'"},
		{"case(s, 'a', 'b')", []CallMistakeKind{MistakeCasePredicate}, "s"},
		{"case(true, 'a', 'x', 'b', 'c')", nil, ""},
		{"case(b, 'a', 'b')", nil, ""},
		{"case(1 == 1, 'a', 'b')", nil, ""},
		{"fromJSON(github.event)", []CallMistakeKind{MistakeFromJSONArgument}, "github.event"},
		{"fromJSON(x.*)", []CallMistakeKind{MistakeFromJSONArgument}, "x.*"},
		{"fromJSON(s)", nil, ""},
		{"false && fromJSON(github.event)", nil, ""},
		{"true || fromJSON(github.event)", nil, ""},
		{"b && fromJSON(github.event)", []CallMistakeKind{MistakeFromJSONArgument}, "github.event"},
		{"case(true, 'a', fromJSON(github.event))", nil, ""},
		{"toJSON(format('{0}'))", []CallMistakeKind{MistakeFormatArguments}, ""},
		{"format()", nil, ""},
		{"case(m, 'a', 'b')", nil, ""},
		{"case(f || s, 'a', 'b')", nil, ""},
		{"case(false, fromJSON(github.event), 'b')", nil, ""},
		{"case(false, 'a', fromJSON(github.event))", []CallMistakeKind{MistakeFromJSONArgument}, "github.event"},
		{"format('x', fromJSON(github.event))", nil, ""},
		{"format('{1}', fromJSON(github.event), fromJSON(github.event))", []CallMistakeKind{MistakeFromJSONArgument}, "github.event"},
	}
	for _, tt := range tests {
		src := tt.src
		got := CallMistakes(mustParse(t, src), refs)
		var kinds []CallMistakeKind
		for _, m := range got {
			kinds = append(kinds, m.Kind)
		}
		if !slices.Equal(kinds, tt.want) {
			t.Errorf("CallMistakes(%q) = %v, want %v", src, kinds, tt.want)
			continue
		}
		if tt.arg != "" {
			sp := got[0].Arg.Span()
			if a := src[sp.Start:sp.End]; a != tt.arg {
				t.Errorf("CallMistakes(%q): Arg %q, want %q", src, a, tt.arg)
			}
		}
	}
}

// TestCallMistakesUpstreamCase runs the inputs of case() of upstream's
// pkg/expressions/semantic_case_test.go (sisakulint 17c2d82) whose number
// of arguments is odd; an even number is CheckNames'. Upstream reports
// every predicate that is not a boolean; the runner stops at the first
// true one, so the
// predicates after a literal true, which upstream reports, are not
// reported here.
func TestCallMistakesUpstreamCase(t *testing.T) {
	refs := typesOf(map[string]Type{"github.event_name": TypeOf(ValueString), "github.ref": TypeOf(ValueString)})
	tests := []struct {
		src      string
		want     int
		upstream bool // whether upstream reports it
	}{
		{"case(true, 'yes', 'no')", 0, false},
		{"case(false, 'a', true, 'b', 'default')", 0, false},
		{"case(github.event_name == 'push', 'pushed', github.event_name == 'pull_request', 'pr', 'other')", 0, false},
		{"case(github.ref == 'main', 'pass', 'fail')", 0, false},
		{"case(true, 1, 0)", 0, false},
		{"case(github.ref == 'refs/heads/main', true, false)", 0, false},
		{"case(true, case(false, 'a', 'b'), 'c')", 0, false},
		{"case(true, 'a', 'not-a-bool', 'b', 'default')", 0, true},
		{"case(true, 'a', true, 'b', 42, 'c', 'default')", 0, true},
		{"case(true)", 0, false},
	}
	for _, tt := range tests {
		if got := CallMistakes(mustParse(t, tt.src), refs); len(got) != tt.want {
			t.Errorf("CallMistakes(%q) = %d mistakes, want %d", tt.src, len(got), tt.want)
		}
	}
}

// TestFormatRefs: the arguments the placeholders of a format string name,
// before its first error.
func TestFormatRefs(t *testing.T) {
	for _, c := range []struct {
		f       string
		args    int
		refs    []bool
		missing bool
	}{
		{"{0}", 2, []bool{true, false}, false},
		{"{1} {0}", 2, []bool{true, true}, false},
		{"{0001}", 2, []bool{false, true}, false},
		{"{0:x}", 2, []bool{true, false}, false},
		{"{{1}} {0}", 2, []bool{true, false}, false},
		{"{0} {2}", 2, []bool{true, false}, true},
		{"{0} {x} {1}", 2, []bool{true, false}, false},
		{"{256} {0}", 1, []bool{false}, false},
	} {
		refs, missing := FormatRefs(c.f, c.args)
		if !slices.Equal(refs, c.refs) || missing != c.missing {
			t.Errorf("FormatRefs(%q, %d) = %v, %v; want %v, %v", c.f, c.args, refs, missing, c.refs, c.missing)
		}
	}
}
