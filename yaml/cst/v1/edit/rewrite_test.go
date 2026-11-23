package edit

import (
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func rewrite(t *testing.T, src, old string, style cst.ScalarStyle, value string) (string, error) {
	t.Helper()
	tr := cst.Parse([]byte(src))
	ed, err := Rewrite(valueOf(t, tr, old), style, value)
	if err != nil {
		return "", err
	}
	return string(mustApply(t, tr, ed).Tree.Bytes()), nil
}

func TestRewrite(t *testing.T) {
	cases := []struct {
		src, old string
		style    cst.ScalarStyle
		value    string
		want     string
	}{
		{"name: 123\n", "123", cst.DoubleQuoted, "123", "name: \"123\"\n"},
		{"a: \"x\"\n", "x", cst.SingleQuoted, "it's", "a: 'it''s'\n"},
		{"a: 'x y'\n", "x y", cst.Plain, "x y", "a: x y\n"},
		{"a: &a !t x\n", "x", cst.DoubleQuoted, "y", "a: &a !t \"y\"\n"},
		{"a: [x, y]\n", "x", cst.DoubleQuoted, "a, b", "a: [\"a, b\", y]\n"},
		{"run: |\n  a\n  b\nnext: c\n", "a\nb\n", cst.DoubleQuoted, "a\nb\n", "run: \"a\\nb\\n\"\nnext: c\n"},
		{"run: | # c\n  a\n", "a\n", cst.DoubleQuoted, "a\n", "run: \"a\\n\" # c\n"},
		{"a:\n", "", cst.DoubleQuoted, "x", "a: \"x\"\n"},
	}
	for _, c := range cases {
		got, err := rewrite(t, c.src, c.old, c.style, c.value)
		if err != nil || got != c.want {
			t.Errorf("%q: Rewrite to %v %q = %q, %v; want %q", c.src, c.style, c.value, got, err, c.want)
		}
	}
}

func TestRewriteRejects(t *testing.T) {
	cases := []struct {
		src, old string
		style    cst.ScalarStyle
		value    string
	}{
		{"a: x\n", "x", cst.Literal, "y\n"},
		{"a: x\n", "x", cst.Folded, "y\n"},
		{"a: x\n", "x", cst.Plain, "b: c"},
		{"a: x\n", "x", cst.Plain, "-"},
		{"a: x\n", "x", cst.SingleQuoted, "a\nb"},
		{"a: [x]\n", "x", cst.Plain, "y,z"},
		// taking the quotes off must not change the type
		{"v: \"3.10\"\n", "3.10", cst.Plain, "3.10"},
		{"a: 'true'\n", "true", cst.Plain, "true"},
		{"a: x\n", "x", cst.Plain, "123"},
	}
	for _, c := range cases {
		if got, err := rewrite(t, c.src, c.old, c.style, c.value); err == nil {
			t.Errorf("%q: Rewrite to %v %q = %q, want an error", c.src, c.style, c.value, got)
		}
	}
}
