package cst

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

const suiteRoot = "../../yaml-test-suite/data-2022-01-17"

var suiteTag = flag.String("suite.tag", "", "run only the cases under tags/<tag>")

var (
	suiteOnce  sync.Once
	suiteCases []suitetest.Case
	suiteErr   error
)

func loadSuite(t *testing.T) []suitetest.Case {
	t.Helper()
	suiteOnce.Do(func() { suiteCases, suiteErr = suitetest.Load(suiteRoot) })
	if suiteErr != nil {
		t.Fatal(suiteErr)
	}
	if *suiteTag == "" {
		return suiteCases
	}
	ents, err := os.ReadDir(filepath.Join(suiteRoot, "tags", *suiteTag))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, e := range ents {
		want[e.Name()] = true
	}
	var cs []suitetest.Case
	for _, c := range suiteCases {
		top, _, _ := strings.Cut(c.ID, "/")
		if want[top] {
			cs = append(cs, c)
		}
	}
	return cs
}

var tally suitetest.Tally

func TestMain(m *testing.M) {
	code := m.Run()
	if r := tally.String(); r != "" {
		fmt.Println("suite:", r)
	}
	os.Exit(code)
}

func runSuite(t *testing.T, check string, want func(suitetest.Case) bool, f func(*testing.T, suitetest.Case)) {
	for _, c := range loadSuite(t) {
		if !want(c) {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			if why, ok := suiteExclude[c.ID]; ok {
				t.Skip("excluded: " + why)
			}
			defer tally.Count(check, t)
			f(t, c)
		})
	}
}

func all(suitetest.Case) bool { return true }

func TestSuiteInvariants(t *testing.T) {
	runSuite(t, "invariants", all, func(t *testing.T, c suitetest.Case) {
		if err := validate(Parse(c.In)); err != nil {
			t.Error(err)
		}
	})
}

func TestSuiteErrors(t *testing.T) {
	runSuite(t, "errors", all, func(t *testing.T, c suitetest.Case) {
		errs := Parse(c.In).Errors()
		if c.Error && len(errs) == 0 {
			t.Errorf("%s: accepted invalid input\n%s", c.Name, c.In)
		}
		if !c.Error && len(errs) > 0 {
			t.Errorf("%s: rejected valid input: %v\n%s", c.Name, errs[0], c.In)
		}
	})
}

func TestSuiteSkeleton(t *testing.T) {
	runSuite(t, "skeleton", func(c suitetest.Case) bool { return !c.Error }, func(t *testing.T, c suitetest.Case) {
		var got, want []string
		for _, e := range events(Parse(c.In)) {
			got = append(got, e.String())
		}
		for _, e := range c.Events {
			want = append(want, e.String())
		}
		if g, w := strings.Join(got, "\n"), strings.Join(want, "\n"); g != w {
			t.Errorf("%s:\ninput:\n%s\ngot:\n%s\nwant:\n%s", c.Name, c.In, g, w)
		}
	})
}
