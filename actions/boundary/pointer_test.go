package boundary

import (
	"strings"
	"testing"
)

// TestParseJSONPointer: the empty string, slashes before tokens and ~0 and
// ~1 are a JSON pointer; a pointer not starting with a slash, and a tilde
// not followed by 0 or 1, are not.
func TestParseJSONPointer(t *testing.T) {
	for _, s := range []string{"", "/", "/a/0", "/a~0b", "/a~1b"} {
		p, err := ParseJSONPointer(s)
		if err != nil || p.String() != s {
			t.Errorf("ParseJSONPointer(%q) = %v, %v", s, p, err)
		}
	}
	if !MustJSONPointer("").IsZero() || MustJSONPointer("/").IsZero() {
		t.Error("only the empty pointer is the whole document")
	}
	for _, s := range []string{"a", "a/b", "/a~", "/a~2"} {
		if _, err := ParseJSONPointer(s); err == nil {
			t.Errorf("ParseJSONPointer(%q) has no error", s)
		}
	}
}

// TestQuoteFoundIn: a quote with a JSON pointer is found only within the
// text of the value the pointer points to; one without is found anywhere
// in the file.
func TestQuoteFoundIn(t *testing.T) {
	const entry = `"slug": "create-an-issue",
        "access": "write"`
	file := `{
  "issues": {
    "title": "Issues",
    "permissions": [
      {
        "slug": "list-issues",
        "access": "read"
      },
      {
        ` + entry + `
      }
    ]
  },
  "a/b~c": {"permissions": ["x"]}
}`
	quote := func(pointer, text string) Quote {
		return Quote{JSONPointer: MustJSONPointer(pointer), Text: text}
	}
	for _, c := range []struct {
		name   string
		quote  Quote
		source string
		want   bool
	}{
		{"within the value", quote("/issues/permissions", entry), file, true},
		{"within an element of an array", quote("/issues/permissions/1", entry), file, true},
		{"not within that element", quote("/issues/permissions/0", entry), file, false},
		{"a key with a slash and a tilde", quote("/a~1b~0c/permissions/0", `"x"`), file, true},
		{"the permission renamed", quote("/issues/permissions", entry), replace(file, `"issues"`, `"pull_requests"`), false},
		{"under another key only", quote("/issues/permissions", entry), replace(file, `"issues"`, `"issues2"`, `"a/b~c"`, `"issues"`), false},
		{"no such value", quote("/issues/permissions/2", entry), file, false},
		{"an index not in decimal", quote("/issues/permissions/01", entry), file, false},
		{"a file not JSON", quote("/issues", "Issues"), "issues: Issues", false},
		{"the whole file", quote("", "issues: Issues"), "issues: Issues", true},
		{"not in the whole file", quote("", "pulls"), "issues: Issues", false},
	} {
		if got := c.quote.FoundIn([]byte(c.source)); got != c.want {
			t.Errorf("%s: FoundIn = %v, want %v", c.name, got, c.want)
		}
	}
}

// replace replaces each old of the pairs with its new, once each, in order.
func replace(s string, pairs ...string) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		if !strings.Contains(s, pairs[i]) {
			panic("no " + pairs[i])
		}
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return s
}
