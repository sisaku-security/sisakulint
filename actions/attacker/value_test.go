package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
)

func TestValues(t *testing.T) {
	login := own{form: formLogin}
	repo := own{form: formRepo}
	branch := chosen{}
	outsider := set(outsiderAssociations)
	for _, c := range []struct {
		name string
		got  expr.Truth
		want expr.Truth
	}{
		{"login == a name", login.Equal(expr.String("dependabot[bot]")), expr.TruthFalse},
		{"login == a number", login.Equal(expr.Number(49699333)), expr.TruthFalse},
		{"login == repository", login.Equal(expr.AbstractValue(repository)), expr.TruthFalse},
		{"repo == repository", repo.Equal(expr.AbstractValue(repository)), expr.TruthFalse},
		{"repo == login", repo.Equal(expr.AbstractValue(login)), expr.TruthUnknown},
		{"repository == repository", repository.Equal(expr.AbstractValue(repository)), expr.TruthTrue},
		{"repository == a name", repository.Equal(expr.String("o/r")), expr.TruthUnknown},
		{"login within 'alice bob'", login.Within("alice bob"), expr.TruthUnknown},
		{"login within '[]'", login.Within("[] -"), expr.TruthFalse},
		{"login prefix '-a'", login.Prefix("-a"), expr.TruthFalse},
		{"login suffix 'a b'", login.Suffix("a b"), expr.TruthUnknown},
		{"branch == main", branch.Equal(expr.String("main")), expr.TruthUnknown},
		{"branch == 'a b'", branch.Equal(expr.String("a b")), expr.TruthFalse},
		{"branch within ''", branch.Within(""), expr.TruthFalse},
		{"outsider == OWNER", outsider.Equal(expr.String("OWNER")), expr.TruthFalse},
		{"outsider == none", outsider.Equal(expr.String("none")), expr.TruthUnknown},
		{"outsider within 'OWNER MEMBER COLLABORATOR'", outsider.Within("owner member collaborator"), expr.TruthFalse},
		{"outsider within 'NONE CONTRIBUTOR'", outsider.Within("none contributor"), expr.TruthUnknown},
		{"set of one == it", set{"x"}.Equal(expr.String("X")), expr.TruthTrue},
		{"login contains alice", login.Contains("alice"), expr.TruthUnknown},
		{"login contains a-", login.Contains("a-"), expr.TruthUnknown},
		{"login contains no space", login.Contains("alice bob"), expr.TruthFalse},
		{"login contains no --", login.Contains("a--b"), expr.TruthFalse},
		{"login contains no /", login.Contains("my-org/"), expr.TruthFalse},
		{"login starts with no -", login.StartsWith("-a"), expr.TruthFalse},
		{"login ends with no -", login.EndsWith("a-"), expr.TruthFalse},
		{"login ends with -a", login.EndsWith("-a"), expr.TruthUnknown},
		{"id contains digits", own{form: formID}.Contains("12"), expr.TruthUnknown},
		{"id contains no letter", own{form: formID}.Contains("a"), expr.TruthFalse},
		{"repo contains no two /", repo.Contains("a/b/c"), expr.TruthFalse},
		{"repo contains an owner", repo.Contains("myorg"), expr.TruthUnknown},
		{"repo starts with no written owner/", repo.StartsWith("myorg/"), expr.TruthFalse},
		{"repo contains a written owner/", repo.Contains("myorg/"), expr.TruthUnknown},
		{"repo ends with /name", repo.EndsWith("/tools"), expr.TruthUnknown},
		{"repo starts with an owner", repo.StartsWith("myorg"), expr.TruthUnknown},
		{"repo ends with a name's end", repo.EndsWith("-tools"), expr.TruthUnknown},
		{"repo contains org/re", repo.Contains("org/re"), expr.TruthUnknown},
		{"repo contains x-", repo.Contains("x-"), expr.TruthUnknown},
		{"repo starts with no -", repo.StartsWith("-x"), expr.TruthFalse},
		{"repo ends with no /", repo.EndsWith("a/"), expr.TruthFalse},
		{"repo contains no space", repo.Contains("a b"), expr.TruthFalse},
		{"branch contains no ..", branch.Contains("a..b"), expr.TruthFalse},
		{"branch contains $(", branch.Contains("$(x)"), expr.TruthUnknown},
		{"outsider contains no member", outsider.Contains("member"), expr.TruthFalse},
		{"outsider may contain contributor", outsider.Contains("contributor"), expr.TruthUnknown},
		{"outsider ends with no owner", outsider.EndsWith("owner"), expr.TruthFalse},
		{"outsider starts with no member", outsider.StartsWith("member"), expr.TruthFalse},
		{"repository contains anything maybe", repository.Contains("x"), expr.TruthUnknown},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.want)
		}
	}
}
