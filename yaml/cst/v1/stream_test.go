package cst

import "testing"

type skelCase struct{ src, want string }

func runSkeleton(t *testing.T, cases []skelCase) {
	t.Helper()
	for _, c := range cases {
		tr := Parse([]byte(c.src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", c.src, err)
			continue
		}
		if errs := tr.Errors(); len(errs) > 0 {
			t.Errorf("%q: unexpected errors %v", c.src, errs)
		}
		if got := skeleton(c.src); got != c.want {
			t.Errorf("%q:\ngot:\n%s\nwant:\n%s", c.src, got, c.want)
		}
	}
}

func TestStreamDocuments(t *testing.T) {
	runSkeleton(t, []skelCase{
		{"", "+STR\n-STR"},
		{"# only comment\n", "+STR\n-STR"},
		{"\n\n  \n# c\n", "+STR\n-STR"},
		{"%YAML 1.2\n---\n", "+STR\n+DOC ---\n=VAL :\n-DOC\n-STR"},
		{"%TAG !e! tag:e.com,2000:\n%FOO bar baz\n--- # c\n", "+STR\n+DOC ---\n=VAL :\n-DOC\n-STR"},
		{"---\n...\n---\n", "+STR\n+DOC ---\n=VAL :\n-DOC ...\n+DOC ---\n=VAL :\n-DOC\n-STR"},
		{"---\n---\n...\n...\n", "+STR\n+DOC ---\n=VAL :\n-DOC\n+DOC ---\n=VAL :\n-DOC ...\n-STR"},
		{"\ufeff# bom\n", "+STR\n-STR"},
		{"---\n...\n\ufeff---\n", "+STR\n+DOC ---\n=VAL :\n-DOC ...\n+DOC ---\n=VAL :\n-DOC\n-STR"},
	})
}

func TestStreamTokens(t *testing.T) {
	tr := Parse([]byte("\ufeff%YAML 1.2\n--- # c\n"))
	var got []string
	for k := range tr.Root().Tokens() {
		got = append(got, k.Kind().String()+"("+string(k.Bytes())+")")
	}
	want := []string{"BOM(\ufeff)", "Directive(%YAML)", "Space( )", "DirectiveParam(1.2)", "Newline(\n)", "DocStart(---)", "Space( )", "Comment(# c)", "Newline(\n)"}
	if len(got) != len(want) {
		t.Fatalf("tokens = %q", got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEncodingError(t *testing.T) {
	for _, src := range []string{"\xff\xfea\x00", "\xfe\xff\x00a", "a\x00b\x00", "\x00\x00\xfe\xff"} {
		tr := Parse([]byte(src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", src, err)
		}
		errs := tr.Errors()
		if len(errs) != 1 || errs[0].Code != ErrEncoding {
			t.Errorf("%q: errors %v, want one ErrEncoding", src, errs)
		}
	}
}

func TestUnparsedContentIsError(t *testing.T) {
	for _, src := range []string{"'unterminated\n", "%YAML 1.2\n", "\"a\" b\n"} {
		tr := Parse([]byte(src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", src, err)
		}
		if len(tr.Errors()) == 0 {
			t.Errorf("%q: no error", src)
		}
	}
}
