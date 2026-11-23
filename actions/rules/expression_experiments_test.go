package rules

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// expressionExpected are the kinds of expression each file of the
// experiments gives, by the
// directory of the commit and the file: a workflow by its name without
// .yml, an action.yml by its directory. A file not named gives none: the
// runs of those files did what they were written for, or failed for what
// the rule declares it does not read (y17 and w07: event-payload; z19:
// the name of a step, as the owner decided).
var expressionExpected = map[string]map[string]string{
	"expression-types/1": {
		"y01": "embedded-object", "y02": "embedded-object", "y04": "failed-step", "y05": "failed-step", "y07": "failed-step",
		"y08": "failed-job", "y09": "ignored-setting", "y10": "ignored-setting", "y11": "unstarted-job", "y12": "unstarted-job",
		"y13": "unstarted-job", "y14": "unstarted-job", "y15": "ignored-setting", "y16": "ignored-setting", "y18": "failed-job",
		"y19": "unstarted-job", "y20": "failed-step", "y22": "failed-step", "c23": "unstarted-caller", "c24": "unstarted-caller",
		"y34": "failed-step",
		// the run succeeded, with the empty string for vars.GITHUB_FOO and
		// vars['a b'], names that no level can define
		"y26": "undefinable-configuration-variable",
	},
	"expression-types-2/1": {
		"z01": "unstarted-job", "z02": "unstarted-job", "z03": "unstarted-job", "z04": "unstarted-job", "z05": "unstarted-job",
		"z06": "unstarted-job", "z07": "unstarted-job", "z08": "unstarted-job", "z10": "ignored-setting", "z11": "ignored-setting",
		"c12": "unstarted-job", "z14": "ignored-setting", "coe": "ignored-setting", "z17": "failed-job", "z18": "failed-job",
		"z20": "failed-step", "z21": "unstarted-job", "z22": "unstarted-job", "z23": "unstarted-job", "z24": "failed-step",
		"envobj": "failed-step", "z28": "failed-job", "z29": "unstarted-job", "z30": "ignored-setting", "z31": "failed-step",
		"c32": "unstarted-caller", "z33": "unstarted-job", "z35": "embedded-object", "z36": "embedded-object",
	},
	"expression-types-3/1": {
		"w01": "unstarted-job", "w02": "unstarted-job", "w03": "failed-job", "w04": "failed-job", "w05": "failed-job",
		"w06": "failed-job", "w08": "failed-job", "w09": "failed-job", "c10": "failed-job", "outobj": "failed-step",
		"w12": "embedded-object",
	},
	"expression-types-4/1": {
		"v01": "unstarted-job", "v02": "unstarted-job", "v03": "unstarted-job", "v04": "unstarted-job", "v05": "unstarted-job",
		"iferr": "failed-step",
	},
	"expression-types-5/1": {
		"u01": "failed-step", "u02": "unstarted-job", "runobj": "failed-step", "wdobj": "failed-step", "withobj": "failed-step",
	},
	"expression-types-6/1": {
		"x01": "unstarted-job", "x02": "failed-job", "x03": "failed-step", "x04": "failed-step", "c05": "unstarted-caller",
		"c06": "unstarted-caller", "x09": "unstarted-job",
	},
	"expression-types-7/1": {"q01": "ignored-setting", "q02": "unstarted-job"},
}

// TestExpressionExperiments runs expression on the tree of each commit of
// the experiments of types, a repository of its own.
func TestExpressionExperiments(t *testing.T) {
	trees, err := filepath.Glob("testdata/observed/expression-types*/*")
	if err != nil || len(trees) != len(expressionExpected) {
		t.Fatalf("%d trees, %v", len(trees), err)
	}
	for _, tree := range trees {
		version := filepath.Base(filepath.Dir(tree)) + "/" + filepath.Base(tree)
		want, ok := expressionExpected[version]
		if !ok {
			t.Errorf("%s: no expectations", tree)
			continue
		}
		fsys := fstest.MapFS{}
		err := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			name, _ := filepath.Rel(tree, p)
			fsys[strings.TrimSuffix(filepath.ToSlash(name), ".txt")] = &fstest.MapFile{Data: b}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][]string{}
		for _, f := range qualityReportFS(t, ExpressionRuleID, fsys, storeOf(t)).QualityFindings {
			key := f.Location.File.Input.String()
			if path.Base(key) == "action.yml" {
				key = path.Base(path.Dir(key))
			} else {
				key = strings.TrimSuffix(path.Base(key), ".yml")
			}
			kind := strings.TrimPrefix(f.Args.KindID().String(), "expression.")
			if !slices.Contains(got[key], kind) {
				got[key] = append(got[key], kind)
			}
		}
		for key, kinds := range got {
			if len(kinds) != 1 || kinds[0] != want[key] {
				t.Errorf("%s %s: %v, want %q", version, key, kinds, want[key])
			}
		}
		for key := range want {
			if got[key] == nil {
				t.Errorf("%s %s: nothing, want %s", version, key, want[key])
			}
		}
	}
}
