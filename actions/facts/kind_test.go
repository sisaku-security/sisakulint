package facts

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestParseKind(t *testing.T) {
	k, err := ParseKind("test.flag")
	if err != nil || k != KindTestFlag {
		t.Errorf("ParseKind(test.flag) = %v, %v", k, err)
	}
	for _, s := range []string{"", "git.nope", "Test.flag", "test.flag "} {
		if _, err := ParseKind(s); err == nil {
			t.Errorf("ParseKind(%q): no error", s)
		}
	}
}

func TestKindJSON(t *testing.T) {
	b, err := json.Marshal(KindTestRepoFlag)
	if err != nil || string(b) != `"test.repo-flag"` {
		t.Errorf("Marshal = %s, %v", b, err)
	}
	var k Kind
	if err := json.Unmarshal(b, &k); err != nil || k != KindTestRepoFlag {
		t.Errorf("Unmarshal = %v, %v", k, err)
	}
	if err := json.Unmarshal([]byte(`"git.nope"`), &k); err == nil {
		t.Error("Unmarshal of an unknown kind: no error")
	}
	if _, err := json.Marshal(KindUnset); err == nil {
		t.Error("Marshal of the zero Kind: no error")
	}
}

func TestQueryKindIsTyped(t *testing.T) {
	if got := (TestFlag{}).Kind(); got != KindTestFlag {
		t.Errorf("TestFlag.Kind = %v", got)
	}
	if got := KindTestCommit.String(); got != "test.commit" {
		t.Errorf("String = %q", got)
	}
}

func TestKindInfoIsTyped(t *testing.T) {
	for _, k := range Kinds() {
		if !strings.HasPrefix(k.Kind.String(), "test.") {
			continue
		}
		if k.Provider != ProviderTest {
			t.Errorf("%v: From = %v, want %v", k.Kind, k.Provider, ProviderTest)
		}
		if !k.Permission.IsZero() {
			t.Errorf("%v: Permission = %v, want none", k.Kind, k.Permission)
		}
	}
	if got := ProviderGitHub.String(); got != "github" {
		t.Errorf("ProviderGitHub = %q", got)
	}
}

func TestGitRefCommit(t *testing.T) {
	a := GitRefCommit{Repo: mustRepo(t, "Actions/Checkout"), Ref: "v4"}
	b := GitRefCommit{Repo: mustRepo(t, "actions/checkout"), Ref: "v4"}
	if a != b {
		t.Error("the same repository in another case is another fact")
	}
	if (GitRefCommit{Repo: a.Repo, Ref: "V4"}) == a {
		t.Error("a ref in another case is the same fact; git refs are case-sensitive")
	}
	enc, err := EncodeQuery(a)
	if err != nil || string(enc) != `{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v4"}` {
		t.Errorf("EncodeQuery = %s, %v", enc, err)
	}
	q, err := DecodeQuery(enc)
	if err != nil || q != Query(a) {
		t.Errorf("DecodeQuery = %#v, %v", q, err)
	}
	k := Kinds()
	i := slices.IndexFunc(k, func(i KindInfo) bool { return i.Kind == KindGitRefCommit })
	if i < 0 || k[i].Provider != ProviderGitHub || k[i].Permission.String() != "contents: read" {
		t.Errorf("KindInfo = %+v", k)
	}
	st, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [
		{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v4"}, "state": "found", "value": {"sha": "11BD71901BBE5B1630CEEA73D27597364C9AF683", "ref": "refs/tags/v4"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Ask(context.Background(), st); got.State != StateFound || got.Value.SHA.String() != "11bd71901bbe5b1630ceea73d27597364c9af683" || got.Value.Ref.String() != "refs/tags/v4" {
		t.Errorf("Ask = %+v", got)
	}
	// a full SHA found as a commit has no ref
	for _, v := range []string{`{"sha": "11bd71901bbe5b1630ceea73d27597364c9af683"}`} {
		if _, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [
			{"query": {"kind": "git.ref-commit", "repo": "a/b", "ref": "11bd71901bbe5b1630ceea73d27597364c9af683"}, "state": "found", "value": ` + v + `}]}`)); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{`"11bd71901bbe5b1630ceea73d27597364c9af683"`, `{"sha": "11bd71901bbe5b1630ceea73d27597364c9af683", "ref": "v4"}`, `{"ref": "refs/tags/v4"}`} {
		if _, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [
			{"query": {"kind": "git.ref-commit", "repo": "a/b", "ref": "v4"}, "state": "found", "value": ` + v + `}]}`)); err == nil {
			t.Errorf("%s: no error", v)
		}
	}
}

func TestGitCommitRef(t *testing.T) {
	sha := func(s string) SHA {
		t.Helper()
		v, err := ParseSHA(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	a := GitCommitRef{Repo: mustRepo(t, "Actions/Checkout"), SHA: sha("11BD71901BBE5B1630CEEA73D27597364C9AF683")}
	b := GitCommitRef{Repo: mustRepo(t, "actions/checkout"), SHA: sha("11bd71901bbe5b1630ceea73d27597364c9af683")}
	if a != b {
		t.Error("the same commit in another case is another fact")
	}
	enc, err := EncodeQuery(a)
	if err != nil || string(enc) != `{"kind":"git.commit-ref","repo":"actions/checkout","sha":"11bd71901bbe5b1630ceea73d27597364c9af683"}` {
		t.Errorf("EncodeQuery = %s, %v", enc, err)
	}
	k := Kinds()
	i := slices.IndexFunc(k, func(i KindInfo) bool { return i.Kind == KindGitCommitRef })
	if i < 0 || k[i].Provider != ProviderGitHub || k[i].Permission.String() != "contents: read" {
		t.Errorf("KindInfo = %+v", k)
	}
	for _, c := range []struct {
		value string
		state State
	}{
		{`"refs/tags/v4"`, StateFound},
		{`"refs/heads/releases/v4"`, StateFound},
		{`"main"`, StateUnknown},
		{`"refs/pull/1/head"`, StateUnknown},
		{`"refs/tags/"`, StateUnknown},
	} {
		st, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [
			{"query": {"kind": "git.commit-ref", "repo": "actions/checkout", "sha": "11bd71901bbe5b1630ceea73d27597364c9af683"}, "state": "found", "value": ` + c.value + `}]}`))
		if c.state == StateUnknown {
			if err == nil {
				// a file whose value is not of the kind is refused as a whole
				if got := b.Ask(context.Background(), st); got.State != StateUnknown {
					t.Errorf("%s: Ask = %+v, want unknown", c.value, got)
				}
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.value, err)
		}
		if got := b.Ask(context.Background(), st); got.State != c.state || got.Value.String() != c.value[1:len(c.value)-1] {
			t.Errorf("%s: Ask = %+v", c.value, got)
		}
	}
}
