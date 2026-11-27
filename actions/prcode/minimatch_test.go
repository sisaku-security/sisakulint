package prcode

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// minimatchCases is testdata/minimatch/cases.json: the cases of the tests
// of minimatch v10.2.4 and v9.0.3 that a name of an artifact can meet, and
// the runs of the actions (see the README.md there).
type minimatchCases struct {
	Match []struct {
		Source   string          `json:"source"`
		Pattern  string          `json:"pattern"`
		Name     string          `json:"name"`
		Versions map[string]bool `json:"versions"`
		Known    bool            `json:"known"`
	} `json:"match"`
	Braces []struct {
		Pattern  string              `json:"pattern"`
		Versions map[string][]string `json:"versions"`
	} `json:"braces"`
}

func readMinimatchCases(t *testing.T) minimatchCases {
	t.Helper()
	b, err := os.ReadFile("testdata/minimatch/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c minimatchCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestMinimatchFixtures: matchArtifactName reads each pattern of the
// table as minimatch reads it, and returns known false for the patterns
// that the table marks as not read.
func TestMinimatchFixtures(t *testing.T) {
	c := readMinimatchCases(t)
	if len(c.Match) == 0 {
		t.Fatal("no cases")
	}
	for _, tc := range c.Match {
		match, known := matchArtifactName(tc.Pattern, tc.Name)
		if known != tc.Known {
			t.Errorf("%s: matchArtifactName(%q, %q): known %v, want %v", tc.Source, tc.Pattern, tc.Name, known, tc.Known)
			continue
		}
		if !known {
			continue
		}
		for v, want := range tc.Versions {
			if match != want {
				t.Errorf("%s: matchArtifactName(%q, %q) = %v, want %v (minimatch %s)", tc.Source, tc.Pattern, tc.Name, match, want, v)
			}
		}
	}
}

// TestExpandBraces: the brace expansion of minimatch (the package
// brace-expansion), as the tests of minimatch give it.
func TestExpandBraces(t *testing.T) {
	c := readMinimatchCases(t)
	if len(c.Braces) == 0 {
		t.Fatal("no cases")
	}
	for _, tc := range c.Braces {
		got, ok := expandBraces(tc.Pattern)
		if !ok {
			t.Errorf("expandBraces(%q): over the bound", tc.Pattern)
		}
		for v, want := range tc.Versions {
			if !slices.Equal(got, want) {
				t.Errorf("expandBraces(%q) = %q, want %q (minimatch %s)", tc.Pattern, got, want, v)
			}
		}
	}
}

// TestMatchArtifactNameBounds: a pattern whose braces the rule does not
// read is not known, and stops at once: more than braceExpandMax names,
// more than braceWorkMax bytes, a number beyond 2^53, a step of 0, a \
// escape with braces, and a set that brace-expansion expands again.
func TestMatchArtifactNameBounds(t *testing.T) {
	for _, p := range []string{
		"part-{1..2000000}",
		strings.Repeat("{a,b}", 21),
		`{a,b}\-x`,
		"part-{9223372036854775806..9223372036854775807}",
		"part-{1..3..0}",
		"part-{1..99999999999999999999}",
		strings.Repeat("{x}", 22) + "{a,b}",
		"z{1..99999}" + strings.Repeat("x", 100),
		"p{1,2}{a},}",
	} {
		start := time.Now()
		if _, known := matchArtifactName(p, "part-1"); known {
			t.Errorf("matchArtifactName(%q): known", p)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("matchArtifactName(%q) took %v", p, d)
		}
	}
	if match, known := matchArtifactName("part-{1..100000}", "part-99999"); !match || !known {
		t.Errorf("part-{1..100000}: %v %v", match, known)
	}
}

// TestJSTrim: the trim of core.getInput, which is JavaScript's, not Go's.
func TestJSTrim(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{" part-* ", "part-*"},
		{"\ufeffpart-*\ufeff", "part-*"},
		{"\u0085part-*\u0085", "\u0085part-*\u0085"},
		{"\u00a0\u3000part-*\u2028", "part-*"},
	} {
		if got := jsTrim(c.in); got != c.want {
			t.Errorf("jsTrim(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
