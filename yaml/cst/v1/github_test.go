package cst

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

// The expected results in this file are what GitHub did with the same
// shapes in a workflow file.

func eventString(t *Tree) string {
	var ls []string
	for _, e := range events(t) {
		ls = append(ls, e.String())
	}
	return strings.Join(ls, "\n")
}

// sameAsSpec fails unless src reads the same in both modes: the same
// errors and the same events.
func sameAsSpec(t *testing.T, src string) {
	t.Helper()
	s, g := Parse([]byte(src)), ParseMode([]byte(src), ModeGitHub)
	if fmt.Sprint(s.Errors()) != fmt.Sprint(g.Errors()) {
		t.Errorf("%q: errors\nspec   %v\ngithub %v", src, s.Errors(), g.Errors())
	}
	if a, b := eventString(s), eventString(g); a != b {
		t.Errorf("%q: events\nspec:\n%s\ngithub:\n%s", src, a, b)
	} else if !sameTree(s, g) {
		t.Errorf("%q: the tokens or nodes differ", src)
	}
	if err := validate(g); err != nil {
		t.Errorf("%q: %v", src, err)
	}
}

// sameTree is whether a and b have the same tokens and nodes; events leave
// out the scalars' bytes.
func sameTree(a, b *Tree) bool {
	return slices.Equal(a.tokens, b.tokens) && slices.Equal(a.nodes, b.nodes)
}

func TestModeAPI(t *testing.T) {
	src := []byte("a: 1\n")
	if m := Parse(src).Mode(); m != ModeSpec {
		t.Errorf("Parse: %v", m)
	}
	if m := ParseMode(src, ModeGitHub).Mode(); m != ModeGitHub {
		t.Errorf("ParseMode(GitHub): %v", m)
	}
	if m := ParseMode(src, Mode(99)).Mode(); m != ModeSpec {
		t.Errorf("ParseMode(99): %v", m)
	}
	for _, m := range []Mode{ModeSpec, ModeGitHub} {
		if got := ParseMode(src, m).Reparse([]byte("b: [\n1]\n")).Mode(); got != m {
			t.Errorf("Reparse of %v: %v", m, got)
		}
	}
}

// GitHub does not look at the columns of the lines inside a
// flow collection.
func TestGitHubFlowColumns(t *testing.T) {
	cases := []struct {
		name, src string
		spec      bool // ModeSpec reports errors
		items     string
	}{
		{"a0 bracket deeper", "m:\n  shard: [\n    1/4, 2/4,\n   ]\n", false, "1/4|2/4"},
		{"a1 bracket at key column", "m:\n  shard: [\n    1/4, 2/4,\n  ]\n", true, "1/4|2/4"},
		{"a2 items at key column", "m:\n  shard: [\n  1/4, 2/4,\n  ]\n", true, "1/4|2/4"},
		{"a3 bracket shallower", "m:\n  shard: [\n    1/4, 2/4,\n ]\n", true, "1/4|2/4"},
		{"a4 content at column 0", "env: {\nA: x\n}\n", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := []byte(c.src)
			if got := len(Parse(src).Errors()) > 0; got != c.spec {
				t.Errorf("ModeSpec errors = %v, want %v: %v", got, c.spec, Parse(src).Errors())
			}
			g := ParseMode(src, ModeGitHub)
			if errs := g.Errors(); len(errs) > 0 {
				t.Fatalf("ModeGitHub: %v", errs)
			}
			if err := validate(g); err != nil {
				t.Fatal(err)
			}
			if c.items == "" {
				m, ok := firstNode(g.Root(), NodeFlowMapping).Mapping()
				if !ok {
					t.Fatal("no flow mapping")
				}
				var kv []string
				for e := range m.Entries() {
					kv = append(kv, string(e.Key.Bytes())+"="+string(e.Value.Bytes()))
				}
				if got := strings.Join(kv, ","); got != "A=x" {
					t.Errorf("entries = %q", got)
				}
				return
			}
			s, ok := firstNode(g.Root(), NodeFlowSequence).Sequence()
			if !ok {
				t.Fatal("no flow sequence")
			}
			var items []string
			for it := range s.Items() {
				items = append(items, string(it.Bytes()))
			}
			if got := strings.Join(items, "|"); got != c.items {
				t.Errorf("items = %q, want %q", got, c.items)
			}
		})
	}
}

// Every real-world workflow runs on GitHub, so none has an error in
// ModeGitHub. The ones ModeSpec rejects have their flow sequence whole.
func TestGitHubRealWorld(t *testing.T) {
	root := filepath.Join(suitetest.CorpusRoot(t), "real-world")
	n, fixed := 0, 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		n++
		g := ParseMode(src, ModeGitHub)
		if errs := g.Errors(); len(errs) > 0 {
			t.Errorf("%s: %v", path, errs)
		}
		if err := validate(g); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if len(Parse(src).Errors()) == 0 {
			return nil
		}
		fixed++
		var walk func(Node)
		walk = func(nd Node) {
			if nd.Kind() == NodeError {
				t.Errorf("%s: Error node at %d", path, nd.Span().Start)
			}
			for e := range nd.Children() {
				if c, ok := e.Node(); ok {
					walk(c)
				}
			}
		}
		walk(g.Root())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 529 || fixed != 7 {
		t.Errorf("%d files, %d with ModeSpec errors; want 529 and 7", n, fixed)
	}
}

// A flow collection without its closing indicator is read again strictly,
// so its errors and recovery are those of ModeSpec.
func TestGitHubUnclosedFlow(t *testing.T) {
	for _, src := range []string{
		"a: [1,\nb: 2\nc: 3\n",
		"a: {x: 1\nb: 2\n",
		"a: [1,",
		"a: [1,\n---\nb: 2\n",
		"a:\n  k: [1,\n b: 2\n",
	} {
		sameAsSpec(t, src)
	}
}

// TestGitHubUnclosedInner: only the inner collection is unclosed. The outermost
// flow collection is read again strictly, so all reads as in ModeSpec.
func TestGitHubUnclosedInner(t *testing.T) {
	sameAsSpec(t, "x:\n  y: { a: [1,\n  }\nb: 2\n")
	sameAsSpec(t, "k:\n  x: [ [1,\n  ], [2,\n]\nb: 1\n")
}

// A document marker at column 0 inside a flow collection is not taken in
// by the loose reading.
func TestGitHubMarkerInFlow(t *testing.T) {
	sameAsSpec(t, "k:\n  x: [a,\n--- ]\n")
	sameAsSpec(t, "k:\n  x: [a,\n--- # c\n      b]\nc: 1\n")
	sameAsSpec(t, "k:\n  x: {a: 1,\n...\n")
}

// Nested unclosed collections cost time linear in the input (the strict
// reading again at every level was once quadratic). The
// time is compared with ACTIONS_SCALE=1 only, as it depends on the machine.
func TestGitHubUnclosedNestedCost(t *testing.T) {
	for _, src := range []string{
		"a:\n  k: " + strings.Repeat("[x, ", 999) + "\nb: 2\n",
		"a:\n  k: " + strings.Repeat("[x, ", 999) + strings.Repeat("y", 4000) + "\nb: 2\n",
		strings.Repeat("[x, ", 999),
		"a:\n  k: " + strings.Repeat("{x: ", 999) + "\nb: 2\n",
	} {
		start := time.Now()
		ParseMode([]byte(src), ModeGitHub)
		g := time.Since(start)
		start = time.Now()
		Parse([]byte(src))
		s := time.Since(start)
		if os.Getenv("ACTIONS_SCALE") == "1" && g > 10*s+100*time.Millisecond {
			t.Errorf("%q...: ModeGitHub %v, ModeSpec %v", src[:20], g, s)
		}
		sameAsSpec(t, src)
	}
}

// TestGitHubFlowLineStart: a comment line and a tab at the start of a line
// inside a flow collection.
func TestGitHubFlowLineStart(t *testing.T) {
	comment := []byte("a:\n  k: [\n# c\n    1]\n")
	for _, m := range []Mode{ModeSpec, ModeGitHub} {
		if errs := ParseMode(comment, m).Errors(); len(errs) > 0 {
			t.Errorf("comment line, mode %v: %v", m, errs)
		}
	}
	tab := []byte("a:\n  k: [\n\t1]\n")
	if len(Parse(tab).Errors()) == 0 {
		t.Error("ModeSpec accepts a tab-indented flow line")
	}
	g := ParseMode(tab, ModeGitHub)
	if errs := g.Errors(); len(errs) > 0 {
		t.Errorf("ModeGitHub: %v", errs)
	}
	if err := validate(g); err != nil {
		t.Error(err)
	}
}

// GitHub does not look at the columns of the continuation lines
// of a quoted scalar, in a block too. The values are checked in scalar.
func TestGitHubQuotedColumns(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"f1 double quoted at column 0", "env:\n  A: \"x\ny\"\n"},
		{"f2 double quoted at key column", "env:\n  A: \"x\n  y\"\n"},
		{"f3 single quoted at column 0", "env:\n  A: 'x\ny'\n"},
		{"f5 in a block sequence", "x:\n  - \"x\ny\"\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := []byte(c.src)
			if len(Parse(src).Errors()) == 0 {
				t.Error("ModeSpec accepts it")
			}
			g := ParseMode(src, ModeGitHub)
			if errs := g.Errors(); len(errs) > 0 {
				t.Errorf("ModeGitHub: %v", errs)
			}
			if err := validate(g); err != nil {
				t.Error(err)
			}
		})
	}
}

// What stays strict in ModeGitHub, and quoted scalars without
// their closing quote.
func TestGitHubStaysStrict(t *testing.T) {
	for _, src := range []string{
		"env:\n  A: x\n  y\n",   // a plain scalar in a block
		"a: &x\nb: 1\n",         // s-separate-lines in a block
		"a: [\n---\n]\n",        // a document marker inside a flow collection
		"a: \"x\n---\ny\"\n",    // a document marker inside a quoted scalar
		"a: \"x\nb: 1\n",        // no closing quote
		"a: 'x\n  b: 1\nc: 2\n", // no closing quote
		"f0: \"x\n   y\"\n",     // valid in both
	} {
		sameAsSpec(t, src)
	}
}

// GitHub rejects an implicit key of a flow mapping
// whose ':' is not on the line the key starts on, or that is longer than
// 1024 characters up to the ':'. The tree is that of ModeSpec.
func TestGitHubFlowKeys(t *testing.T) {
	K := func(n int) string { return strings.Repeat("K", n) }
	cases := []struct {
		name, src string
		spec      bool // ModeSpec reports errors
		want      []ErrorCode
	}{
		{"c0", "env: {\n A: x\n }\n", false, nil},
		{"c1 VJP3/01", "env: {\n A\n :\n x\n }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"c2", "env: {\n A\n : x\n }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"c3", "env: {\n A:\n x\n }\n", false, nil},
		{"d1 flow sequence pair", "x: [ a\n : b ]\n", true, nil},
		{"d1c", "x: [ a:\n b ]\n", false, nil},
		{"d2 double quoted", "env: { \"A\"\n : x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d3 single quoted", "env: { 'A'\n : x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d4 explicit", "env: { ? A\n : x }\n", false, nil},
		{"d5 multi-line plain", "env: { A\n B: x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d6 multi-line quoted", "env: { \"A\n B\": x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d7 comment", "env: { A # c\n : x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d8 blank line", "env: {\n A\n\n : x\n }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"d9 explicit multi-line", "env: { ? A\n B\n : x }\n", false, nil},
		{"d10 block", "env:\n  A\n  : x\n", true, nil},
		{"d11 second entry", "env: { A: x, B\n : y }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"e0 1023", "env: { " + K(1023) + ": x }\n", false, nil},
		{"e1 1030", "env: { " + K(1030) + ": x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		// GitHub: the count is characters (code points) from
		// the start of the key to the ':'.
		{"1024", "{ " + K(1024) + ": x }\n", false, nil},
		{"1025", "{ " + K(1025) + ": x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"1023 and a space", "{ " + K(1023) + " : x }\n", false, nil},
		{"1024 and a space", "{ " + K(1024) + " : x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"quoted 1022", "{ \"" + K(1022) + "\": x }\n", false, nil},
		{"quoted 1023", "{ \"" + K(1023) + "\": x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"BMP 1024", "{ " + strings.Repeat("\xe3\x81\x82", 1024) + ": x }\n", false, nil},
		{"BMP 1025", "{ " + strings.Repeat("\xe3\x81\x82", 1025) + ": x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"astral 513", "{ " + strings.Repeat("\U0001F600", 513) + ": x }\n", false, nil},
		{"astral 1024", "{ " + strings.Repeat("\U0001F600", 1024) + ": x }\n", false, nil},
		{"astral 1025", "{ " + strings.Repeat("\U0001F600", 1025) + ": x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"1023 and an astral", "{ " + K(1023) + "\U0001F600: x }\n", false, nil},
		{"1024 and an astral", "{ " + K(1024) + "\U0001F600: x }\n", false, []ErrorCode{ErrImplicitKeyLength}},
		{"both", "{ " + K(1030) + "\n : x }\n", false, []ErrorCode{ErrImplicitKeyLine, ErrImplicitKeyLength}},
		{"in a flow sequence", "[ {a\n: b} ]\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"anchor on the key's line", "{ &k a\n: b }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"empty key", "{ : x }\n", false, nil},
		// as YamlDotNet 5.3.0 reads them
		{"CRLF", "{ a\r\n : b }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"CR", "{ a\r : b }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"flow collection key", "{ [a,\n b]: x }\n", false, []ErrorCode{ErrImplicitKeyLine}},
		{"explicit flow collection key", "{ ? [a,\n b]: x }\n", false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := []byte(c.src)
			s, g := Parse(src), ParseMode(src, ModeGitHub)
			if got := len(s.Errors()) > 0; got != c.spec {
				t.Errorf("ModeSpec errors = %v, want %v: %v", got, c.spec, s.Errors())
			}
			want := c.want
			if c.spec {
				want = codes(s)
			}
			if got := codes(g); !slices.Equal(got, want) {
				t.Errorf("ModeGitHub errors = %v, want %v", g.Errors(), want)
			}
			if a, b := eventString(s), eventString(g); a != b {
				t.Errorf("events differ\nspec:\n%s\ngithub:\n%s", a, b)
			}
			if err := validate(g); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestGitHubFlowKeySpans(t *testing.T) {
	src := "env: {\n A\n :\n x\n }\n"
	e := ParseMode([]byte(src), ModeGitHub).Errors()
	if colon := strings.Index(src, ":\n x"); len(e) != 1 || e[0].Span != (Span{colon, colon + 1}) {
		t.Errorf("a colon before a line break: %v, want the ':' at %d", e, colon)
	}
	key := strings.Repeat("K", 1030)
	src = "env: { " + key + ": x }\n"
	e = ParseMode([]byte(src), ModeGitHub).Errors()
	if at := strings.Index(src, "K"); len(e) != 1 || e[0].Span != (Span{at, at + len(key)}) {
		t.Errorf("a key of 1030 characters: %v, want the key at %d", e, at)
	}
}

// Many unclosed flow collections in a row, and unclosed
// collections nested past the depth limit. Once one is unclosed, the rest of
// the document is read strictly, so the time is that of ModeSpec, and the
// errors too (no ErrDepth from a loose reading given up). The time is
// compared with ACTIONS_SCALE=1 only, as it depends on the machine.
func TestGitHubManyUnclosedCost(t *testing.T) {
	for _, src := range []string{
		strings.Repeat("k: {a: 1,\n", 2000),
		strings.Repeat("k: [a,\n", 2000),
		strings.Repeat("k: [\n", 1000) + strings.Repeat("]", 1000),
		"a:\n  k: [\n" + strings.Repeat("[\n", 1200) + "\nb: 1\n",
		strings.Repeat("k: {a: 1,\n", 600),
	} {
		start := time.Now()
		ParseMode([]byte(src), ModeGitHub)
		g := time.Since(start)
		start = time.Now()
		Parse([]byte(src))
		s := time.Since(start)
		if os.Getenv("ACTIONS_SCALE") == "1" && g > 10*s+100*time.Millisecond {
			t.Errorf("%q...: ModeGitHub %v, ModeSpec %v", src[:12], g, s)
		}
		sameAsSpec(t, src)
	}
}

// Nested implicit keys each once scanned their whole key.
// ACTIONS_SCALE=1 only, as the time it compares depends on the machine.
func TestGitHubNestedKeysCost(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of ModeGitHub and ModeSpec")
	}
	src := "k: " + strings.Repeat("{ ", 8000) + "a" + strings.Repeat(": b }", 8000)
	start := time.Now()
	ParseMode([]byte(src), ModeGitHub)
	g := time.Since(start)
	start = time.Now()
	Parse([]byte(src))
	if s := time.Since(start); g > 10*s+20*time.Millisecond {
		t.Errorf("ModeGitHub %v, ModeSpec %v", g, s)
	}
}
