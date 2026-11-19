package edit

import (
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// valueOf is the scalar of tr whose value is want.
func valueOf(t *testing.T, tr *cst.Tree, want string) scalar.Value {
	t.Helper()
	var found []scalar.Value
	var walk func(cst.Node)
	walk = func(n cst.Node) {
		if v, ok := scalar.Decode(n); ok && v.String() == want {
			found = append(found, v)
		}
		for e := range n.Children() {
			if c, ok := e.Node(); ok {
				walk(c)
			}
		}
	}
	walk(tr.Root())
	if len(found) != 1 {
		t.Fatalf("%d scalars with value %q", len(found), want)
	}
	return found[0]
}

// replace replaces sub, the first occurrence in the value old of the
// scalar of src, by text and applies it.
func replace(t *testing.T, src, old, sub, text string) (string, error) {
	t.Helper()
	tr := cst.Parse([]byte(src))
	v := valueOf(t, tr, old)
	s := strings.Index(old, sub)
	if s < 0 {
		t.Fatalf("%q not in %q", sub, old)
	}
	ed, err := Replace(v, s, s+len(sub), text)
	if err != nil {
		return "", err
	}
	res := mustApply(t, tr, ed)
	return string(res.Tree.Bytes()), nil
}

func TestReplace(t *testing.T) {
	cases := []struct {
		src, old, sub, text, want string
	}{
		{"a: bcd\n", "bcd", "c", "xx", "a: bxxd\n"},
		{"a: 'it''s x'\n", "it's x", "x", "y'z", "a: 'it''s y''z'\n"},
		{"a: \"t\\x41b\"\n", "tAb", "b", "\"\n", "a: \"t\\x41\\\"\\n\"\n"},
		{"a: \"one\n  two\"\n", "one two", "two", "2", "a: \"one\n  2\"\n"},
		{"a: >\n  one\n  two\n", "one two\n", "two", "2", "a: >\n  one\n  2\n"},
		{"a: |\n  one\n  two\n", "one\ntwo\n", "two", "2\n3", "a: |\n  one\n  2\n  3\n"},
		{"a: !!str 123\n", "123", "123", "abc", "a: !!str abc\n"},
		{"a:\n", "", "", "x", "a: x\n"},
		{"- &x\n", "", "", "y", "- &x y\n"},
	}
	for _, c := range cases {
		got, err := replace(t, c.src, c.old, c.sub, c.text)
		if err != nil || got != c.want {
			t.Errorf("%q: replace %q by %q = %q, %v; want %q", c.src, c.sub, c.text, got, err, c.want)
		}
	}
}

func TestReplaceRejects(t *testing.T) {
	cases := []struct {
		src, old, sub, text string
	}{
		{"a: \"\\xe9\"\n", "\xc3\xa9", "\xc3", "x"}, // cuts a made segment
		{"a: 'x'\n", "x", "x", "a\nb"},              // single-quoted line break
		{"a: bc\n", "bc", "b", "*"},                 // leading indicator
		{"a: bc\n", "bc", "b", " "},                 // leading white
		{"a: bc\n", "bc", "c", "c:"},                // trailing ':'
		{"a: bc\n", "bc", "c", "x #y"},              // comment
		{"a: [bc]\n", "bc", "c", "x,y"},             // flow indicator in a flow collection
		{"name: build\n", "build", "build", "123"},  // str becomes int
		{"a: 123\n", "123", "123", "abc"},           // int becomes str
		{"a: bc\n", "bc", "c", "\xff"},              // invalid UTF-8
		{"a: |\n", "", "", "x"},                     // an empty block scalar has no exact place
		{"a: |\n  x\n", "x\n", "x", " y"},           // the first line would change the indentation
	}
	for _, c := range cases {
		if got, err := replace(t, c.src, c.old, c.sub, c.text); err == nil {
			t.Errorf("%q: replace %q by %q = %q, want an error", c.src, c.sub, c.text, got)
		}
	}
}

// Replace checks the value it makes, not what the bytes around the scalar
// make of it: a continuation line of "---" starts a document.
func TestReplaceCheckedByApply(t *testing.T) {
	src := "a\nb\n"
	tr := cst.Parse([]byte(src))
	v := valueOf(t, tr, "a b")
	ed, err := Replace(v, 2, 3, "---")
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if res, err := Apply(tr, []Edit{ed}); err == nil {
		t.Errorf("Apply = %q, want an error", res.Tree.Bytes())
	}
}

// The next line's indentation is in no segment of a block scalar, so a
// range ending in a line feed takes it along.
func TestReplaceBlockLines(t *testing.T) {
	src := "run: |\n  echo a\n  echo b\n  echo c\n"
	cases := []struct{ sub, text, want string }{
		{"echo b\n", "", "run: |\n  echo a\n  echo c\n"},
		{"echo b\n", "X\n", "run: |\n  echo a\n  X\n  echo c\n"},
		{"echo b\n", "X\nY\n", "run: |\n  echo a\n  X\n  Y\n  echo c\n"},
		{"b\n", "", "run: |\n  echo a\n  echo echo c\n"},
		{"a", "a\nZ", "run: |\n  echo a\n  Z\n  echo b\n  echo c\n"},
	}
	for _, c := range cases {
		got, err := replace(t, src, "echo a\necho b\necho c\n", c.sub, c.text)
		if err != nil || got != c.want {
			t.Errorf("replace %q by %q = %q, %v; want %q", c.sub, c.text, got, err, c.want)
		}
	}
}

// TestReplaceCRLF: lines added to a CRLF block scalar end in CRLF.
func TestReplaceCRLF(t *testing.T) {
	got, err := replace(t, "run: |\r\n  a\r\n  b\r\n", "a\nb\n", "a", "x\ny")
	if err != nil || got != "run: |\r\n  x\r\n  y\r\n  b\r\n" {
		t.Errorf("got %q, %v", got, err)
	}
}

// An empty scalar starts where the next token does, which may be another
// scalar (the empty value of "? b" and the key "c"): their edits are
// checked apart.
func TestReplaceScalarsAtOnePlace(t *testing.T) {
	src := "? a\n? b\nc:\n"
	tr := cst.Parse([]byte(src))
	var edits []Edit
	for n := range allScalars(tr) {
		v, _ := decode(n)
		text := v.String()
		if text != "" {
			text += text
		}
		ed, err := Replace(v, 0, len(v.String()), text)
		if err != nil {
			t.Fatalf("%q: %v", v.String(), err)
		}
		edits = append(edits, ed)
	}
	res := mustApply(t, tr, edits...)
	if got := string(res.Tree.Bytes()); got != "? aa\n? bb\ncc:\n" {
		t.Errorf("got %q", got)
	}
}

// Text ending in a line feed before an empty line leaves it empty.
func TestReplaceBlockBlankLines(t *testing.T) {
	cases := []struct{ src, old, sub, text, want string }{
		{"run: |\n  a\n\n  b\n", "a\n\nb\n", "a\n", "x\n", "run: |\n  x\n\n  b\n"},
		{"run: |\n  echo a\n  echo b\n", "echo a\necho b\n", "a", "a\nZ\n", "run: |\n  echo a\n  Z\n\n  echo b\n"},
		{"run: |\n  a\n   \n  b\n", "a\n \nb\n", "a\n", "x\n", "run: |\n  x\n   \n  b\n"},
	}
	for _, c := range cases {
		got, err := replace(t, c.src, c.old, c.sub, c.text)
		if err != nil || got != c.want {
			t.Errorf("%q: replace %q by %q = %q, %v; want %q", c.src, c.sub, c.text, got, err, c.want)
		}
	}
}
