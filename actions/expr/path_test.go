package expr

import (
	"strings"
	"testing"
)

func pathString(p []PathElem) string {
	var parts []string
	for _, e := range p {
		switch {
		case e.Star:
			parts = append(parts, "*")
		case e.Dynamic != nil:
			parts = append(parts, "["+show(e.Dynamic)+"]")
		default:
			parts = append(parts, e.Name)
		}
	}
	return strings.Join(parts, " ")
}

func TestAccessPath(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" when AccessPath is false
	}{
		{"github", "github"},
		{"github.event.issue.title", "github event issue title"},
		{"github['event']['issue'].title", "github event issue title"},
		{"GITHUB.Event.issue.title", "GITHUB Event issue title"},
		{"a.*.b", "a * b"},
		{"a[*].b", "a * b"},
		{"a[b]", "a [b]"},
		{"a[0]", "a [0]"},
		{"(a).b", "a b"},
		{"fromJSON(x).a", ""},
		{"a == b", ""},
		{"'x'", ""},
	}
	for _, tt := range tests {
		n, errs := Parse(tt.in)
		if len(errs) > 0 {
			t.Fatalf("Parse(%q): %v", tt.in, errs)
		}
		p, ok := AccessPath(n)
		if got := pathString(p); ok != (tt.want != "") || got != tt.want {
			t.Errorf("AccessPath(%q) = %q, %v; want %q", tt.in, got, ok, tt.want)
		}
	}
}

func TestAccessPathEqual(t *testing.T) {
	a, _ := Parse("github.event.issue.title")
	b, _ := Parse("GITHUB['Event'].ISSUE['title']")
	pa, _ := AccessPath(a)
	pb, _ := AccessPath(b)
	if len(pa) != len(pb) {
		t.Fatalf("%v %v", pa, pb)
	}
	for i := range pa {
		if !EqualName(pa[i].Name, pb[i].Name) {
			t.Errorf("elem %d: %q != %q", i, pa[i].Name, pb[i].Name)
		}
	}
}

// GitHub compares keys after lowering each character.
func TestEqualName(t *testing.T) {
	const (
		dottedI = "\xc4\xb0" // U+0130
		dotless = "\xc4\xb1" // U+0131
		kelvin  = "\xe2\x84\xaa"
		sharpS  = "\xc3\x9f"
	)
	tests := []struct {
		a, b string
		want bool
	}{
		{"FOO", "foo", true},
		{"build", "Build", true},
		{"X" + sharpS, "XSS", false},
		{dottedI + "X", "iX", true},
		{kelvin + "X", "kX", true},
		{dottedI + "X", "IX", true},
		{dotless + "X", "IX", false},
		{"a", "ab", false},
		// Invalid UTF-8 compares by its bytes.
		{"\xff", "\xfe", false},
		{"\xff", "\xff", true},
		{"", "", true},
	}
	for _, tt := range tests {
		if got := EqualName(tt.a, tt.b); got != tt.want {
			t.Errorf("EqualName(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
		if got := FoldName(tt.a) == FoldName(tt.b); got != tt.want {
			t.Errorf("FoldName(%q) == FoldName(%q) is %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestHasPrefix: names compare as GitHub compares them; a star or a
// dynamic index matches no name.
func TestHasPrefix(t *testing.T) {
	path := func(src string) []PathElem {
		n, errs := Parse(src)
		if errs != nil {
			t.Fatalf("Parse(%q) errors %v", src, errs)
		}
		p, ok := AccessPath(n)
		if !ok {
			t.Fatalf("%q is no access path", src)
		}
		return p
	}
	for _, c := range []struct {
		src   string
		names []string
		want  bool
	}{
		{"GitHub.Event.action", []string{"github", "event"}, true},
		{"github['event'].x", []string{"github", "event", "x"}, true},
		{"github", []string{"github", "event"}, false},
		{"github.*", []string{"github", "event"}, false},
		{"github[x]", []string{"github", "x"}, false},
		{"env.a", nil, true},
	} {
		if got := HasPrefix(path(c.src), c.names...); got != c.want {
			t.Errorf("HasPrefix(%s, %q) = %v", c.src, c.names, got)
		}
	}
}

func TestPathString(t *testing.T) {
	for src, want := range map[string]string{
		"github.head_ref":                   "github.head_ref",
		"github['event']['issue'].title":    "github.event.issue.title",
		"github.event.commits.*.message":    "github.event.commits.*.message",
		"github.event.commits[matrix.i].id": "github.event.commits[*].id",
		"github.event.pages[0].title":       "github.event.pages[0].title",
	} {
		n, errs := Parse(src)
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		p, _ := AccessPath(n)
		if got := PathString(p); got != want {
			t.Errorf("%s: %s", src, got)
		}
	}
}

func TestPathIs(t *testing.T) {
	for _, c := range []struct {
		src  string
		want bool
	}{
		{"github.token", true},
		{"github . token", true},
		{"github['token']", true},
		{"GITHUB.Token", true},
		{"(github).token", true},
		{"github.token.x", false},
		{"github", false},
		{"github[x]", false},
		{"github.*", false},
		{"format('{0}', github.token)", false},
	} {
		n, err := Parse(c.src)
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got := IsPath(n, "github", "token"); got != c.want {
			t.Errorf("%s: IsPath %v, want %v", c.src, got, c.want)
		}
	}
	if PathIs(nil) != true || PathIs([]PathElem{{Name: "a"}}) {
		t.Errorf("PathIs of no names")
	}
}
