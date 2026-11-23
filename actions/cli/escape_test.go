package cli

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain ${{ x }}", "plain ${{ x }}"},
		{"tab\tstays", "tab\tstays"},
		{"a\nb", `a\nb`},
		{"\x1b[2J", `\x1b[2J`},
		{"\x00\x07\x7f", `\x00\x07\x7f`},
		{"\u0085\u009b", `\u0085\u009b`},
		{"a\u202eb\u2066c\u200fd\u200ee", `a\u202eb\u2066c\u200fd\u200ee`},
		{"\xff", `\xff`},
		{"a\u061cb", `a\u061cb`},
		{"日本語", "日本語"},
	} {
		if got := clean(c.in); got != c.want {
			t.Errorf("clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPadWidth(t *testing.T) {
	s := "\tab\x1b日"
	if got, want := width(s), utf8.RuneCountInString(clean(s)); got != want {
		t.Errorf("width = %d, want %d", got, want)
	}
	if got := pad(s); got != "\t"+strings.Repeat(" ", width(s)-1) {
		t.Errorf("pad(%q) = %q", s, got)
	}
}

func FuzzClean(f *testing.F) {
	for _, s := range []string{"", "a\x1b[31mb", "\u202e", "\xff\xfe", "\t\n\r"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := clean(s)
		if !utf8.ValidString(out) {
			t.Fatalf("clean(%q) = %q, not UTF-8", s, out)
		}
		for _, r := range out {
			if hazard(r) {
				t.Fatalf("clean(%q) = %q has %U", s, out, r)
			}
		}
	})
}
