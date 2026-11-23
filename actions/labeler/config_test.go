package labeler

import (
	"errors"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// reachOf is the reach of label in the configuration text read as f; it
// fails t when the text does not read.
func reachOf(t *testing.T, text string, f Format, label string) []analysis.AutomaticLabel {
	t.Helper()
	labels, err := ParseConfig([]byte(text), f)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	r, ok := labels[label]
	if !ok {
		t.Fatalf("no label %s in %v", label, labels)
	}
	if r.Never() {
		return nil
	}
	return r.Labels()
}

var (
	free       = []analysis.AutomaticLabel{analysis.AutomaticLabelFree}
	paths      = []analysis.AutomaticLabel{analysis.AutomaticLabelPaths}
	baseBranch = []analysis.AutomaticLabel{analysis.AutomaticLabelBaseBranch}
	both       = []analysis.AutomaticLabel{analysis.AutomaticLabelPaths, analysis.AutomaticLabelBaseBranch}
)

func TestParseConfigKeys(t *testing.T) {
	for _, c := range []struct {
		name, text string
		f          Format
		want       []analysis.AutomaticLabel
	}{
		// https://github.com/fooagen/zellij/blob/039c8d5962dd341bb58dd7dcd09eb2cf7389ac7a/.github/labeler.yaml:
		// the two conditions under one changed-files are an any, so the
		// first adds the label with any other file.
		{"two conditions of changed-files", `documentation:
  - changed-files:
      - any-glob-to-any-file:
          - 'pages/**/*.md'
          - 'pages/**/*.mdx'
      - all-globs-to-all-files:
          - 'pages/**/*.md'
          - 'pages/**/*.mdx'
`, FormatKeys, free},
		{"all globs to all files", "l:\n  - changed-files:\n      - all-globs-to-all-files: ['pages/**']\n", FormatKeys, paths},
		{"any glob to all files with a glob of every path", "l:\n  - changed-files:\n      - any-glob-to-all-files: ['**']\n", FormatKeys, free},
		{"any glob to all files", "l:\n  - changed-files:\n      - any-glob-to-all-files: ['pages/**', 'site/**']\n", FormatKeys, paths},
		{"all globs to any file", "l:\n  - changed-files:\n      - all-globs-to-any-file: ['pages/**', '**/*.md']\n", FormatKeys, free},
		{"head branch", "l:\n  - head-branch: ['^feat']\n", FormatKeys, free},
		{"base branch", "l:\n  - base-branch: ['^main$']\n", FormatKeys, baseBranch},
		{"base branch of every name", "l:\n  - base-branch: ['.*']\n", FormatKeys, free},
		{"all of paths and a base branch", "l:\n  - all:\n      - changed-files:\n          - all-globs-to-all-files: ['pages/**']\n      - base-branch: ['^main$']\n", FormatKeys, both},
		{"all of a free and paths", "l:\n  - all:\n      - changed-files:\n          - any-glob-to-any-file: ['src/**']\n      - changed-files:\n          - all-globs-to-all-files: ['src/**']\n", FormatKeys, paths},
		{"any of paths and a head branch", "l:\n  - any:\n      - changed-files:\n          - all-globs-to-all-files: ['pages/**']\n      - head-branch: ['^pages/']\n", FormatKeys, free},
		{"two conditions of the label, both kept", "l:\n  - changed-files:\n      - any-glob-to-any-file: ['src/**']\n  - all:\n      - base-branch: ['^main$']\n", FormatKeys, baseBranch},
		{"empty any", "l:\n  - any: []\n", FormatKeys, nil},
		{"no files limit in v7", "max-files-changed: 0\nl:\n  - changed-files:\n      - any-glob-to-any-file: ['src/**']\n", FormatKeysLimits, nil},
		{"a limit of one file in v7", "max-files-changed: 1\nl:\n  - changed-files:\n      - any-glob-to-any-file: ['src/**']\n", FormatKeysLimits, paths},
		{"no labels limit in v7", "changed-files-labels-limit: 0\nl:\n  - changed-files:\n      - any-glob-to-any-file: ['src/**']\n", FormatKeysLimits, nil},
		{"a limit of files keeps a head branch", "max-files-changed: 0\nl:\n  - head-branch: ['^x']\n", FormatKeysLimits, free},
	} {
		t.Run(c.name, func(t *testing.T) {
			label := "l"
			if c.name == "two conditions of changed-files" {
				label = "documentation"
			}
			if got := reachOf(t, c.text, c.f, label); !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseConfigKeysErrors(t *testing.T) {
	for _, c := range []struct {
		name, text string
		f          Format
	}{
		{"a label of strings", "l:\n  - 'src/**'\n", FormatKeys},
		{"an unknown key of changed-files", "l:\n  - changed-files:\n      - any-file: ['x']\n", FormatKeys},
		{"a limit in v5 is a label that is not a list", "max-files-changed: 3\nl:\n  - head-branch: ['^x']\n", FormatKeys},
		{"a limit that is not a number", "max-files-changed: many\n", FormatKeysLimits},
		{"a label that is a mapping", "l:\n  changed-files: x\n", FormatKeys},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(c.text), c.f); err == nil || errors.Is(err, ErrUnsupportedSyntax) {
				t.Errorf("err = %v, want an error the labeler throws", err)
			}
		})
	}
}

func TestParseConfigAnyAll(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       []analysis.AutomaticLabel
	}{
		{"a string", "l: 'src/**'\n", free},
		{"a list of strings", "l:\n  - 'src/**'\n  - 'lib/**'\n", free},
		{"all", "l:\n  - all: ['pages/**']\n", paths},
		{"any", "l:\n  - any: ['pages/**', '**/*.md']\n", free},
		{"all and any", "l:\n  - any: ['pages/**']\n    all: ['pages/**']\n", paths},
		{"all of every path", "l:\n  - all: ['**']\n", free},
		// an entry with neither any nor all matches every pull request
		{"a configuration of v5", "l:\n  - changed-files:\n      - all-globs-to-all-files: ['pages/**']\n", free},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := reachOf(t, c.text, FormatAnyAll, "l"); !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
	if _, err := ParseConfig([]byte("l: 3\n"), FormatAnyAll); err == nil {
		t.Error("a label that is a number reads; the labeler throws")
	}
}

func TestParseConfigGlobs(t *testing.T) {
	if got := reachOf(t, "l:\n  - 'src/**'\n", FormatGlobs, "l"); !slices.Equal(got, free) {
		t.Errorf("got %v, want %v", got, free)
	}
	if got := reachOf(t, "l: []\n", FormatGlobs, "l"); got != nil {
		t.Errorf("an empty list: got %v, want never", got)
	}
	if _, err := ParseConfig([]byte("l:\n  - any: ['src/**']\n"), FormatGlobs); err == nil {
		t.Error("an object reads in v2; minimatch throws on it")
	}
}

func TestParseConfigSyntax(t *testing.T) {
	if _, err := ParseConfig([]byte("l:\n  - head-branch: ['^a']\nl:\n  - head-branch: ['^b']\n"), FormatKeys); err == nil || errors.Is(err, ErrUnsupportedSyntax) {
		t.Errorf("a key twice: err = %v, want an error the labeler throws", err)
	}
	for _, text := range []string{
		"base: &b\n  - head-branch: ['^a']\nl: *b\n",
		"l:\n  - <<: {head-branch: ['^a']}\n",
		"l: !!seq\n  - head-branch: ['^a']\n",
	} {
		if _, err := ParseConfig([]byte(text), FormatKeys); !errors.Is(err, ErrUnsupportedSyntax) {
			t.Errorf("%q: err = %v, want ErrUnsupportedSyntax", text, err)
		}
	}
	if _, err := ParseConfig([]byte("l: [\n"), FormatKeys); err == nil {
		t.Error("YAML that does not parse reads")
	}
	labels, err := ParseConfig(nil, FormatKeys)
	if err != nil || len(labels) != 0 {
		t.Errorf("an empty file: %v, %v; want no labels and no error", labels, err)
	}
}

// TestParseConfigKeysFirstAny: a key of a condition goes into the first any
// of the label, an any that the label writes too (get-label-configs.ts,
// findIndex(mc => !!mc['any'])).
func TestParseConfigKeysFirstAny(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       []analysis.AutomaticLabel
	}{
		{"an empty any and a key", "l:\n  - any: []\n  - changed-files:\n      - any-glob-to-any-file: ['a/**']\n", free},
		{"an any and a key in one item", "l:\n  - any:\n      - changed-files:\n          - any-glob-to-all-files: []\n    head-branch: x\n", free},
		{"an any of a base branch and a head branch", "l:\n  - any:\n      - base-branch: '^release$'\n  - head-branch: ['^x']\n", free},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := reachOf(t, c.text, FormatKeys, "l"); !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseConfigEdges(t *testing.T) {
	for _, c := range []struct {
		name, text string
		f          Format
		want       []analysis.AutomaticLabel
	}{
		// toBranchMatchConfig reads a value that is not truthy as none
		{"an empty head branch", "l:\n  - head-branch: ''\n", FormatKeys, nil},
		{"an empty base branch", "l:\n  - base-branch: ''\n", FormatKeys, nil},
		// configUsesChangedFiles counts a key of changed-files with no globs
		{"no files and a key with no globs", "max-files-changed: 0\nl:\n  - all:\n      - changed-files:\n          - all-globs-to-all-files: []\n", FormatKeysLimits, nil},
		// js-yaml reads 1e1, 10.0 and 0x0A as the number 10
		{"a limit 1e1", "max-files-changed: 1e1\nl:\n  - head-branch: ['^x']\n", FormatKeysLimits, free},
		{"a limit 10.0", "max-files-changed: 10.0\nl:\n  - head-branch: ['^x']\n", FormatKeysLimits, free},
		{"a limit 0x0A", "max-files-changed: 0x0A\nl:\n  - head-branch: ['^x']\n", FormatKeysLimits, free},
	} {
		t.Run(c.name, func(t *testing.T) {
			labels, err := ParseConfig([]byte(c.text), c.f)
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			var got []analysis.AutomaticLabel
			if r, ok := labels["l"]; ok && !r.Never() {
				got = r.Labels()
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
