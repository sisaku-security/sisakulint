package expr

import (
	"strings"
	"testing"
)

func kinds(toks []token) string {
	var b strings.Builder
	for i, k := range toks {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k.kind.String())
	}
	return b.String()
}

func TestLex(t *testing.T) {
	tests := []struct {
		in   string
		want string // token kinds; "" for an error
	}{
		{"a", "NamedValue"},
		{"a.b", "NamedValue Dereference PropertyName"},
		{"a.b-c.d_1", "NamedValue Dereference PropertyName Dereference PropertyName"},
		{"steps.my-step.outputs", "NamedValue Dereference PropertyName Dereference PropertyName"},
		{"a[0]", "NamedValue StartIndex Number EndIndex"},
		{"a.*", "NamedValue Dereference Wildcard"},
		{"a[*]", "NamedValue StartIndex Wildcard EndIndex"},
		{"f()", "Function StartParameters EndParameters"},
		{"f (1, 'x')", "Function StartParameters Number Separator String EndParameters"},
		{"(a)", "StartGroup NamedValue EndGroup"},
		{"!a", "LogicalOperator NamedValue"},
		{"a == b", "NamedValue LogicalOperator NamedValue"},
		{"a != b && c || !d", "NamedValue LogicalOperator NamedValue LogicalOperator NamedValue LogicalOperator LogicalOperator NamedValue"},
		{"a < 1 <= 2 > 3 >= 4", "NamedValue LogicalOperator Number LogicalOperator Number LogicalOperator Number LogicalOperator Number"},
		{"null", "Null"},
		{"true", "Boolean"},
		{"false", "Boolean"},
		{"True", "NamedValue"},
		{"a.true", "NamedValue Dereference PropertyName"},
		{"NaN", "Number"},
		{"Infinity", "Number"},
		// Numbers (the runner's ExpressionUtility.ParseNumber).
		{"1", "Number"},
		{"-1", "Number"},
		{"+1", "Number"},
		{"1.5", "Number"},
		{".5", "Number"},
		{"5.", "Number"},
		{"1e3", "Number"},
		{"1E-3", "Number"},
		{"0x1F", "Number"},
		{"0xffffffff", "Number"},
		{"0o17", "Number"},
		{"-Infinity", "Number"},
		// Double.TryParse takes the infinity symbol with a sign, in any case.
		{"+Infinity", "Number"},
		{"-infinity", "Number"},
		{"+INFINITY", "Number"},
		{"-NaN", ""},
		{"1 == .5", "Number LogicalOperator Number"},
		{"1.2.3", ""},
		{"0X1F", ""},
		{"0x", ""},
		{"0x100000000", ""},
		{"0o8", ""},
		{"1+2", ""},
		{"1e", ""},
		{"-", ""},
		// Operators alone.
		{"a = b", ""},
		{"a & b", ""},
		{"a | b", ""},
		// Strings.
		{"'a''b''c'", "String"},
		{"''", "String"},
		{"'a", ""},
		// Grammar checks of the lexer (CheckLastToken).
		{"'x'.y", ""},
		{"a b", ""},
		{"a.1", ""},
		{"(", "StartGroup"},
		{")", ""},
		{"a]", ""},
		{"a,b", ""},
		{"f(a,b)", "Function StartParameters NamedValue Separator NamedValue EndParameters"},
		{"é", ""},
		{"a.é", ""},
	}
	for _, tt := range tests {
		toks, err := lex(tt.in)
		if tt.want == "" {
			if err == nil {
				t.Errorf("lex(%q) = %s, want an error", tt.in, kinds(toks))
			}
			continue
		}
		if err != nil {
			t.Errorf("lex(%q) error %v, want %s", tt.in, err, tt.want)
			continue
		}
		if got := kinds(toks); got != tt.want {
			t.Errorf("lex(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestLexString(t *testing.T) {
	// every '' is one '.
	toks, err := lex("'a''b''c'")
	if err != nil || len(toks) != 1 || toks[0].str != "a'b'c" || toks[0].span != (Span{0, 9}) {
		t.Fatalf("lex = %+v, %v", toks, err)
	}
}

func TestLexSpans(t *testing.T) {
	in := "  foo.bar [ 'x' ]"
	toks, err := lex(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foo", ".", "bar", "[", "'x'", "]"}
	for i, k := range toks {
		if got := in[k.span.Start:k.span.End]; got != want[i] {
			t.Errorf("token %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestLexErrorSpan(t *testing.T) {
	_, err := lex("a == 1.2.3")
	if err == nil || err.Code != ErrUnexpected || err.Span != (Span{5, 10}) {
		t.Fatalf("err = %+v", err)
	}
}
