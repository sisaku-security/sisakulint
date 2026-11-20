package expr

import (
	"strings"
	"testing"
)

func TestCheckNames(t *testing.T) {
	github := Names{}.WithContext(ContextGithub)
	stepIf := github.WithFunc(FuncFailure, Arity{0, 0})
	jobIf := github.WithFunc(FuncFailure, Arity{0, MaxArgs})
	args := func(n int) string { return strings.Repeat(", 'a'", n) }
	tests := []struct {
		src     string
		allowed Names
		want    []ErrorCode
		msg     string // the message of the first error, when not ""
		span    string // the source under the first error's span, when not ""
	}{
		{"github.sha", github, nil, "", ""},
		{"GITHUB.SHA", github, nil, "", ""},
		{"toJSON(github)", github, nil, "", ""},
		{"TOJSON(github)", github, nil, "", ""},
		{"secrets.a", github, []ErrorCode{ErrUnknownName}, "Unrecognized named-value: 'secrets'; the contexts available here are github", "secrets"},
		{"withJson()", github, []ErrorCode{ErrUnknownFunction}, "Unrecognized function: 'withJson'", "withJson"},
		{"always()", github, []ErrorCode{ErrUnknownFunction}, "Unrecognized function: 'always'", "always"},
		{"contains('a', 'b', 'c')", github, []ErrorCode{ErrTooMany}, "Too many parameters supplied: 'contains'", "contains('a', 'b', 'c')"},
		{"toJSON()", github, []ErrorCode{ErrTooFew}, "Too few parameters supplied: 'toJSON'", ""},
		{"failure('a')", stepIf, []ErrorCode{ErrTooMany}, "", ""},
		{"failure('a')", jobIf, nil, "", ""},
		{"Failure()", stepIf, nil, "", ""},
		{"case(true, 'a')", github, []ErrorCode{ErrTooFew}, "", ""},
		{"case(true, 'a', false, 'b')", github, []ErrorCode{ErrEven}, "Even number of parameters supplied, requires an odd number of parameters: 'case'", ""},
		{"case(true, 'a', 'b')", github, nil, "", ""},
		{"format('{0}'" + args(254) + ")", github, nil, "", ""},
		{"format('{0}'" + args(255) + ")", github, []ErrorCode{ErrTooMany}, "", ""},
		{"secrets.a == env.b", github, []ErrorCode{ErrUnknownName, ErrUnknownName}, "", ""},
		{"toJSON(secrets.a, 'b')", github, []ErrorCode{ErrTooMany, ErrUnknownName}, "", ""},
	}
	for _, tt := range tests {
		n, perrs := Parse(tt.src)
		if len(perrs) > 0 {
			t.Fatalf("%s: %v", tt.src, perrs)
		}
		errs := CheckNames(n, tt.allowed)
		var got []ErrorCode
		for _, e := range errs {
			got = append(got, e.Code)
		}
		if len(got) != len(tt.want) {
			t.Errorf("%s: errors %v, want %v", tt.src, errs, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%s: errors %v, want %v", tt.src, errs, tt.want)
			}
		}
		if len(errs) == 0 {
			continue
		}
		if tt.msg != "" && errs[0].Msg != tt.msg {
			t.Errorf("%s: message %q, want %q", tt.src, errs[0].Msg, tt.msg)
		}
		if sp := errs[0].Span; tt.span != "" && tt.src[sp.Start:sp.End] != tt.span {
			t.Errorf("%s: span %q, want %q", tt.src, tt.src[sp.Start:sp.End], tt.span)
		}
	}
}

func TestNamesUnion(t *testing.T) {
	if !(Names{}).IsZero() {
		t.Error("the zero Names is not zero")
	}
	a := Names{}.WithContext(ContextGithub).WithFunc(FuncFailure, Arity{0, 0})
	b := Names{}.WithContext(ContextSteps).WithFunc(FuncFailure, Arity{0, MaxArgs}).WithFunc(FuncHashFiles, Arity{1, 255})
	u := a.Union(b)
	if u.IsZero() {
		t.Fatal("the union is zero")
	}
	if got := u.Contexts(); len(got) != 2 || got[0] != ContextGithub || got[1] != ContextSteps {
		t.Errorf("contexts %v, want github steps", got)
	}
	n, _ := Parse("failure('a') && hashFiles('x') && steps.a")
	if errs := CheckNames(n, u); len(errs) != 0 {
		t.Errorf("union: %v", errs)
	}
	if a.Union(a) != a {
		t.Error("a union with itself changed")
	}
}

func TestParseNames(t *testing.T) {
	for _, s := range []string{"github", "GitHub", "jobs", "env"} {
		if _, ok := ParseContextName(s); !ok {
			t.Errorf("%s is no context", s)
		}
	}
	if _, ok := ParseContextName("nope"); ok {
		t.Error("nope is a context")
	}
	if f, ok := ParseScopedFunc("HashFiles"); !ok || f != FuncHashFiles || f.String() != "hashFiles" {
		t.Errorf("hashFiles: %v %v", f, ok)
	}
	if c, _ := ParseContextName("Matrix"); c.String() != "matrix" {
		t.Errorf("matrix is %s", c)
	}
}
