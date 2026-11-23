package cst

import (
	"maps"
	"os"
	"slices"
	"testing"
)

// suiteGitHub lists the yaml-test-suite cases whose judgment (error or not)
// ModeGitHub changes, with the rule of ModeGitHub that changes it.
// YamlDotNet 5.3.0 judges each of them as ModeGitHub does.
// VJP3/00 is not here: rule 1 accepts its columns, rule 2 rejects its key.
var suiteGitHub = map[string]string{
	"4MUZ/00":  "rule 2: the key's ':' is on the next line",
	"4MUZ/01":  "rule 2: the key's ':' is on the next line",
	"4MUZ/02":  "rule 2: the key's ':' is on the next line",
	"5MUD":     "rule 2: the key's ':' is on the next line",
	"9SA2":     "rule 2: a quoted key over two lines",
	"K3WX":     "rule 2: a comment between the key and its ':'",
	"NJ66":     "rule 2: a plain key over two lines",
	"UT92":     "rule 2: a plain key over two lines",
	"VJP3/01":  "rule 2: the key and its ':' on separate lines",
	"9C9N":     "rule 1: flow sequence items at column 0",
	"Y79Y/003": "rule 1: a tab at the start of a flow sequence line",
	"DK95/01":  "rule 1: a tab at the start of a quoted scalar's line",
	"QB6E":     "rule 1: quoted scalar lines at column 0",
}

func TestSuiteGitHub(t *testing.T) {
	got := map[string]bool{}
	for _, c := range loadSuite(t) {
		s := len(Parse(c.In).Errors()) > 0
		g := ParseMode(c.In, ModeGitHub)
		if err := validate(g); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
		if s != (len(g.Errors()) > 0) {
			got[c.ID] = true
			t.Logf("%s: ModeSpec %v, ModeGitHub %v %q", c.ID, s, g.Errors(), c.In)
		}
	}
	if a, b := slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(suiteGitHub)); !slices.Equal(a, b) {
		t.Errorf("changed %v\nlisted  %v", a, b)
	}
}

// sameTreeOrGitHubKeys fails unless src, which has no errors in ModeSpec,
// reads to the same events in ModeGitHub with no errors other than those
// of rules 2 and 3.
func sameTreeOrGitHubKeys(t testing.TB, name string, src []byte) {
	s, g := Parse(src), ParseMode(src, ModeGitHub)
	if err := validate(g); err != nil {
		t.Errorf("%s: %v", name, err)
	}
	if len(s.Errors()) > 0 {
		return
	}
	for _, e := range g.Errors() {
		if e.Code != ErrImplicitKeyLine && e.Code != ErrImplicitKeyLength {
			t.Errorf("%s: ModeGitHub adds %v", name, e)
		}
	}
	if a, b := eventString(s), eventString(g); a != b {
		t.Errorf("%s: events differ\nspec:\n%s\ngithub:\n%s", name, a, b)
	} else if !sameTree(s, g) {
		t.Errorf("%s: the tokens or nodes differ", name)
	}
}

// TestGitHubSameTree checks the bound on what ModeGitHub changes,
// over the suite and the corpus. The corpus is sampled, 1 file in 10,
// unless CST_CORPUS=full.
func TestGitHubSameTree(t *testing.T) {
	for _, c := range loadSuite(t) {
		sameTreeOrGitHubKeys(t, c.ID, c.In)
	}
	full := os.Getenv("CST_CORPUS") == "full"
	for i, path := range corpusFiles(t) {
		if !full && i%10 != 0 {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sameTreeOrGitHubKeys(t, path, src)
	}
}
