package cst

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

func TestBlockScalars(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"|\n a\n b\n", doc1("=VAL |")},
		{">-\n a\n\n b\n", doc1("=VAL >")},
		{"|2\n   a\n", doc1("=VAL |")},
		{"|+\n a\n\n", doc1("=VAL |")},
		{"--- |\n  x\n", "+STR\n+DOC ---\n=VAL |\n-DOC\n-STR"},
		{"--- &a !t >\n  x\n", "+STR\n+DOC ---\n=VAL &a <tag> >\n-DOC\n-STR"},
		{"| # c\n x\n", doc1("=VAL |")},
		{"|\n", doc1("=VAL |")},
		{"|\n  a\n # trail\n# more\n", doc1("=VAL |")},
	})
}

func TestBlockScalarTokens(t *testing.T) {
	src := "|\n  cat <<EOF\n  \tindented\n\n  EOF\n"
	tr := Parse([]byte(src))
	if errs := tr.Errors(); len(errs) > 0 {
		t.Fatalf("errors %v", errs)
	}
	want := "BlockHeader(|) Newline(\n) Space(  ) BlockContent(cat <<EOF) Newline(\n) Space(  ) BlockContent(\tindented) Newline(\n) Newline(\n) Space(  ) BlockContent(EOF) Newline(\n)"
	if got := tokens(tr); got != want {
		t.Errorf("tokens:\ngot  %s\nwant %s", got, want)
	}
}

func TestBlockScalarTrailCommentsOutsideNode(t *testing.T) {
	tr := Parse([]byte("|\n  a\n # trail\n"))
	s := firstNode(tr.Root(), NodeScalar)
	if got := string(s.Bytes()); got != "|\n  a\n" {
		t.Errorf("scalar bytes = %q", got)
	}
}

func TestBlockScalarErrors(t *testing.T) {
	for _, c := range []struct {
		src  string
		code ErrorCode
	}{
		{"--- |\n  a\n\tb\n", ErrUnexpected}, // a tab where indentation is expected ends the scalar
		{"|\n   \n  a\n", ErrIndent},         // a leading empty line more indented than the content
		{"| x\n a\n", ErrUnexpected},
		{"|0\n a\n", ErrUnexpected},
	} {
		tr := Parse([]byte(c.src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", c.src, err)
		}
		var codes []string
		found := false
		for _, e := range tr.Errors() {
			codes = append(codes, e.Error())
			found = found || e.Code == c.code
		}
		if !found {
			t.Errorf("%q: errors [%s], want code %d", c.src, strings.Join(codes, "; "), c.code)
		}
	}
}

func TestBlockCollections(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"a: b\nc: d\n", doc1("+MAP\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n-MAP")},
		{"- a\n- b: c\n  d: e\n", doc1("+SEQ\n=VAL :\n+MAP\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n-MAP\n-SEQ")},
		{"? a\n: b\n", doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{"? a\n", doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{"a:\n- b\n", doc1("+MAP\n=VAL :\n+SEQ\n=VAL :\n-SEQ\n-MAP")},
		{"&x\na: b\n", doc1("+MAP &x\n=VAL :\n=VAL :\n-MAP")},
		{"key:\n", doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{": v\n", doc1("+MAP\n=VAL :\n=VAL :\n-MAP")},
		{"- - a\n  - b\n- c\n", doc1("+SEQ\n+SEQ\n=VAL :\n=VAL :\n-SEQ\n=VAL :\n-SEQ")},
		{"-\n  a\n-\n", doc1("+SEQ\n=VAL :\n=VAL :\n-SEQ")},
		{"a: |\n  x\n\n  y\nb: c\n", doc1("+MAP\n=VAL :\n=VAL |\n=VAL :\n=VAL :\n-MAP")},
		{"a:\n  b:\n    c: d\n  e: [f, g]\n", doc1("+MAP\n=VAL :\n+MAP\n=VAL :\n+MAP\n=VAL :\n=VAL :\n-MAP\n=VAL :\n+SEQ []\n=VAL :\n=VAL :\n-SEQ\n-MAP\n-MAP")},
		{"\"a\": b\n'c': [d]\n[e]: f\n", doc1("+MAP\n=VAL \"\n=VAL :\n=VAL '\n+SEQ []\n=VAL :\n-SEQ\n+SEQ []\n=VAL :\n-SEQ\n=VAL :\n-MAP")},
		{"a: b # c\n# d\ne: f\n", doc1("+MAP\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n-MAP")},
		{"a: !!str\nb: &x\n", doc1("+MAP\n=VAL :\n=VAL <tag> :\n=VAL :\n=VAL &x :\n-MAP")},
		{"--- \na: b\n...\n", "+STR\n+DOC ---\n+MAP\n=VAL :\n=VAL :\n-MAP\n-DOC ...\n-STR"},
		{"if: ${{ a }}\nrun: echo ${{ x }}\nk: ${{ a }}-${{ b }}\n", doc1("+MAP\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n-MAP")},
	})
}

func TestBlockCollectionErrors(t *testing.T) {
	for _, src := range []string{
		"a: |\n\t b\n",      // a tab in place of the block scalar's indentation
		"[${{ a }}]\n",      // '{' starts a flow mapping inside a flow sequence
		"a: b\n c: d\n",     // a more indented line after a plain value
		"--- a: b\n",        // a block mapping cannot start on the --- line
		"a:\n  - b\n - c\n", // entries with different indentation
	} {
		tr := Parse([]byte(src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", src, err)
		}
		if len(tr.Errors()) == 0 {
			t.Errorf("%q: no error", src)
		}
	}
}

func TestExpressionScalarsArePlain(t *testing.T) {
	tr := Parse([]byte("if: ${{ a }}\nrun: echo ${{ x }}\nk: ${{ a }}-${{ b }}\n"))
	m, _ := firstNode(tr.Root(), NodeBlockMapping).Mapping()
	var got []string
	for e := range m.Entries() {
		if e.Value.Style() != Plain {
			t.Errorf("%q is %v", e.Value.Bytes(), e.Value.Style())
		}
		got = append(got, string(e.Value.Bytes()))
	}
	if want := "${{ a }}|echo ${{ x }}|${{ a }}-${{ b }}"; strings.Join(got, "|") != want {
		t.Errorf("values = %q", got)
	}
}

func TestCRLFMatchesLF(t *testing.T) {
	root := filepath.Join(suitetest.CorpusRoot(t), "real-world")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, d := range dirs {
		fs, _ := filepath.Glob(filepath.Join(root, d.Name(), "*.yml"))
		if len(fs) > 0 {
			path = fs[0]
			break
		}
	}
	lf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
	a, b := Parse(lf), Parse(crlf)
	if len(a.Errors()) > 0 || len(b.Errors()) > 0 {
		t.Fatalf("%s: errors LF %v CRLF %v", path, a.Errors(), b.Errors())
	}
	if err := validate(b); err != nil {
		t.Fatal(err)
	}
	if skeleton(string(lf)) != skeleton(string(crlf)) {
		t.Fatalf("%s: skeletons differ", path)
	}
	lines := func(tr *Tree) []int {
		var ls []int
		var walk func(Node)
		walk = func(n Node) {
			if n.Kind() == NodeScalar {
				ls = append(ls, tr.Position(n.Span().Start).Line)
			}
			for e := range n.Children() {
				if c, ok := e.Node(); ok {
					walk(c)
				}
			}
		}
		walk(tr.Root())
		return ls
	}
	la, lb := lines(a), lines(b)
	if len(la) == 0 || fmt.Sprint(la) != fmt.Sprint(lb) {
		t.Errorf("%s: scalar lines LF %v CRLF %v", path, la, lb)
	}
}
