package jsonschema

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "write testdata/suite-loaded.golden.json")

// suiteSkips are the tests of the suite that the subset reads differently
// from draft 2020-12 on purpose, by file, the description of the group and
// that of the test, with why.
var suiteSkips = map[[3]string]string{}

type suiteGroup struct {
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Tests       []struct {
		Description string          `json:"description"`
		Data        json.RawMessage `json:"data"`
		Valid       bool            `json:"valid"`
	} `json:"tests"`
}

// TestSuite runs the groups of the JSON Schema Test Suite (testdata/suite)
// whose schema Load accepts, and keeps how many groups of each file it
// runs, so that a change of Load cannot drop them unseen.
func TestSuite(t *testing.T) {
	files, err := filepath.Glob("testdata/suite/*.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]int{}
	used := map[[3]string]bool{}
	for _, f := range files {
		name := filepath.Base(f)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var groups []suiteGroup
		if err := json.Unmarshal(b, &groups); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		loaded[name] = 0
		for _, g := range groups {
			set, err := Load(map[string][]byte{"t.json": g.Schema}, Options{})
			if err != nil {
				continue
			}
			loaded[name]++
			for _, c := range g.Tests {
				key := [3]string{name, g.Description, c.Description}
				if _, skip := suiteSkips[key]; skip {
					used[key] = true
					continue
				}
				err := set.Validate("t.json", "#", c.Data)
				if (err == nil) != c.Valid {
					t.Errorf("%s: %s: %s: Validate(%s) = %v, want valid=%v", name, g.Description, c.Description, c.Data, err, c.Valid)
				}
			}
		}
	}
	for k := range suiteSkips {
		if !used[k] {
			t.Errorf("suiteSkips has %q, which is no test of a group that Load accepts", k)
		}
	}
	got, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := "testdata/suite-loaded.golden.json"
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the groups that Load accepts, by file:\n%s\nwant (%s):\n%s", got, golden, want)
	}
}
