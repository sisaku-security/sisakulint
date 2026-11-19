package cst

import (
	"strings"
	"testing"
)

func doc1(events string) string { return "+STR\n+DOC\n" + events + "\n-DOC\n-STR" }

func tokens(tr *Tree) string {
	var got []string
	for k := range tr.Root().Tokens() {
		got = append(got, k.Kind().String()+"("+string(k.Bytes())+")")
	}
	return strings.Join(got, " ")
}

func TestFlowScalars(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"a", doc1("=VAL :")},
		{"a b # c\n", doc1("=VAL :")},
		{"a#b", doc1("=VAL :")},
		{"'a''b'", doc1("=VAL '")},
		{"\"a\\tb\"", doc1("=VAL \"")},
		{"&x a", doc1("=VAL &x :")},
		{"!!str a", doc1("=VAL <tag> :")},
		{"!<tag:x> &y 'a'", doc1("=VAL &y <tag> '")},
		{"%TAG !e! tag:e,2000:\n--- !e!foo a", "+STR\n+DOC ---\n=VAL <tag> :\n-DOC\n-STR"},
		{"&x", doc1("=VAL &x :")},
		{"*x", doc1("=ALI *x")},
		{"a\n b\n\n c", doc1("=VAL :")},
		{"\"a\n  b\"", doc1("=VAL \"")},
		{"'a\n\n  b  '\n", doc1("=VAL '")},
		{"\"a \\\n  b\"", doc1("=VAL \"")},
		{"a\n...\n\ufeff---\nb\n", "+STR\n+DOC\n=VAL :\n-DOC ...\n+DOC ---\n=VAL :\n-DOC\n-STR"},
		{"--- a\n", "+STR\n+DOC ---\n=VAL :\n-DOC\n-STR"},
	})
}

func TestFlowScalarTokens(t *testing.T) {
	cases := []struct{ src, want string }{
		{"\"a\n  b\"", `DoubleQuoted("a) Newline(` + "\n" + `) Space(  ) DoubleQuoted(b")`},
		{"a  \n\n b", "Plain(a) Space(  ) Newline(\n) Newline(\n) Space( ) Plain(b)"},
		{"\"a \\\n b\"", `DoubleQuoted("a \) Newline(` + "\n" + `) Space( ) DoubleQuoted(b")`},
		{"&x !t a", "Anchor(&x) Space( ) Tag(!t) Space( ) Plain(a)"},
		// the white space of an escape at the end of a line is not trailing
		// white space ([62] c-ns-esc-char, DE56)
		{"\"a\\\t \n b\"", "DoubleQuoted(\"a\\\t) Space( ) Newline(\n) Space( ) DoubleQuoted(b\")"},
		{"\"a\\  \n b\"", "DoubleQuoted(\"a\\ ) Space( ) Newline(\n) Space( ) DoubleQuoted(b\")"},
		{"\"a\\\\\t\n b\"", "DoubleQuoted(\"a\\\\) Space(\t) Newline(\n) Space( ) DoubleQuoted(b\")"},
	}
	for _, c := range cases {
		if got := tokens(Parse([]byte(c.src))); got != c.want {
			t.Errorf("%q:\ngot  %s\nwant %s", c.src, got, c.want)
		}
	}
}

func TestPlainStopsAtDocumentMarker(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"a\n---\nb\n", "+STR\n+DOC\n=VAL :\n-DOC\n+DOC ---\n=VAL :\n-DOC\n-STR"},
	})
}

func TestInvalidEscape(t *testing.T) {
	tr := Parse([]byte(`"\q"`))
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	errs := tr.Errors()
	if len(errs) != 1 || errs[0].Code != ErrInvalidEscape || errs[0].Span != (Span{1, 3}) {
		t.Errorf("errors = %v", errs)
	}
	if skeleton(`"\q"`) != doc1(`=VAL "`) {
		t.Errorf("skeleton = %s", skeleton(`"\q"`))
	}
}

func TestFlowCollections(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"[a, b]", doc1("+SEQ []\n=VAL :\n=VAL :\n-SEQ")},
		{"[]", doc1("+SEQ []\n-SEQ")},
		{"{}", doc1("+MAP {}\n-MAP")},
		{"[a, ]", doc1("+SEQ []\n=VAL :\n-SEQ")},
		{"{a: b, c}", doc1("+MAP {}\n=VAL :\n=VAL :\n=VAL :\n=VAL :\n-MAP")},
		{"[a: b]", doc1("+SEQ []\n+MAP {}\n=VAL :\n=VAL :\n-MAP\n-SEQ")},
		{"[{a: [b]}, \"c\": d]", doc1("+SEQ []\n+MAP {}\n=VAL :\n+SEQ []\n=VAL :\n-SEQ\n-MAP\n+MAP {}\n=VAL \"\n=VAL :\n-MAP\n-SEQ")},
		{"{? a}", doc1("+MAP {}\n=VAL :\n=VAL :\n-MAP")},
		{"{? }", doc1("+MAP {}\n=VAL :\n=VAL :\n-MAP")},
		{"[a,\n b]", doc1("+SEQ []\n=VAL :\n=VAL :\n-SEQ")},
		{"{\"a\":b}", doc1("+MAP {}\n=VAL \"\n=VAL :\n-MAP")},
		{"{: b}", doc1("+MAP {}\n=VAL :\n=VAL :\n-MAP")},
		{"&x [a]", doc1("+SEQ [] &x\n=VAL :\n-SEQ")},
		{"[&a x, *a]", doc1("+SEQ []\n=VAL &a :\n=ALI *a\n-SEQ")},
		{"{a: [b, c], d: {e: f}}", doc1("+MAP {}\n=VAL :\n+SEQ []\n=VAL :\n=VAL :\n-SEQ\n=VAL :\n+MAP {}\n=VAL :\n=VAL :\n-MAP\n-MAP")},
	})
}

func TestFlowAttemptErrorsRollBack(t *testing.T) {
	tr := Parse([]byte(`["\q", b]`))
	if errs := tr.Errors(); len(errs) != 1 || errs[0].Code != ErrInvalidEscape {
		t.Errorf("errors = %v, want one ErrInvalidEscape", errs)
	}
}

// Quotes inside plain scalars must not hide the ':' of a flow pair.
func TestFlowPairWithQuoteInPlainKey(t *testing.T) {
	pair := doc1("+SEQ []\n+MAP {}\n=VAL :\n=VAL :\n-MAP\n-SEQ")
	runSkeleton(t, []skelCase{
		{"[it's a: b]", pair},
		{"[can't stop: now]", pair},
		{"[5\" wide: x]", pair},
		{"[it's: 'x']", doc1("+SEQ []\n+MAP {}\n=VAL :\n=VAL '\n-MAP\n-SEQ")},
		{"- [ a, it's: b ]", doc1("+SEQ\n+SEQ []\n=VAL :\n+MAP {}\n=VAL :\n=VAL :\n-MAP\n-SEQ\n-SEQ")},
		{"[\"a,b]\": c]", doc1("+SEQ []\n+MAP {}\n=VAL \"\n=VAL :\n-MAP\n-SEQ")},
		{"[&a \"]\": c]", doc1("+SEQ []\n+MAP {}\n=VAL &a \"\n=VAL :\n-MAP\n-SEQ")},
		{"[{a: \"]\"}: c]", doc1("+SEQ []\n+MAP {}\n+MAP {}\n=VAL :\n=VAL \"\n-MAP\n=VAL :\n-MAP\n-SEQ")},
	})
}
