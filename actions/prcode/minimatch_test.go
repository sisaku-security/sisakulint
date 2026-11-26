package prcode

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
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
// table as minimatch reads it, and does not read the patterns that the
// releases of minimatch read differently.
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
