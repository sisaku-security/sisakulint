package lint

import "testing"

func TestParseKindArgumentName(t *testing.T) {
	for _, s := range []string{"expr_ref", "a", "controlled_on"} {
		if n, err := ParseKindArgumentName(s); err != nil || n.String() != s {
			t.Errorf("ParseKindArgumentName(%q) = %v, %v", s, n, err)
		}
	}
	for _, s := range []string{"", "Expr", "expr-ref", "_a", "a_", "a__b", "1a"} {
		if _, err := ParseKindArgumentName(s); err == nil {
			t.Errorf("ParseKindArgumentName(%q): want an error", s)
		}
	}
}
