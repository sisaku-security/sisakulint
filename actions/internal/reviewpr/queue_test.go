package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

// doc is a review document of rule made up for the tests: meta.md, or the
// document of the example <what>/<id>.
func doc(rule, p string) rules.ReviewDocument {
	d := rules.ReviewDocument{Rule: lint.MustRuleID(rule), Path: rules.MustReviewPath(p), Text: "# " + rule + " " + p + "\n"}
	if p != "meta.md" {
		what, id, _ := strings.Cut(strings.TrimSuffix(p, ".md"), "/")
		x := rules.ExampleLocation{Rule: d.Rule, ID: id}
		for _, w := range []lint.ExampleWhat{lint.ExampleFalsePositive, lint.ExampleUndetected, lint.ExampleInconclusive, lint.ExampleTruePositive, lint.ExampleTrueNegative} {
			if w.String() == what {
				x.What = w
			}
		}
		d.Example = &x
	}
	return d
}

// changed is the review of rule whose meta.md (when meta) and n examples
// differ, with the stale approved documents stale.
func changed(rule string, meta bool, n int, stale ...string) rules.RuleReview {
	rv := rules.RuleReview{Rule: lint.MustRuleID(rule)}
	for _, p := range stale {
		rv.Stale = append(rv.Stale, rules.MustReviewPath(p))
	}
	if meta {
		rv.Changed = append(rv.Changed, doc(rule, "meta.md"))
	}
	for i := range n {
		rv.Changed = append(rv.Changed, doc(rule, fmt.Sprintf("false-positive/%02d.md", i+1)))
	}
	rv.Reviewed = len(rv.Changed) == 0 && len(stale) == 0
	return rv
}

func TestBatchOf(t *testing.T) {
	write, remove := batchOf(changed("a", true, 12, "undetected/old.md", "true-positive/gone.md"), 10)
	var paths []string
	for _, d := range write {
		paths = append(paths, d.Path.String())
	}
	if len(write) != 11 || paths[0] != "meta.md" || paths[10] != "false-positive/10.md" {
		t.Errorf("write %v", paths)
	}
	if len(remove) != 2 || remove[0].String() != "undetected/old.md" || remove[1].String() != "true-positive/gone.md" {
		t.Errorf("remove %v", remove)
	}
	write, _ = batchOf(changed("a", false, 3), 10)
	if len(write) != 3 || write[0].Path.String() != "false-positive/01.md" {
		t.Errorf("without meta.md: %v", write)
	}
}

func TestOpenReviews(t *testing.T) {
	r := &fakeRunner{out: map[string]string{"gh pr list": "[]"}}
	if open, err := openReviews(r); err != nil || len(open) != 0 {
		t.Fatalf("no PR: %v %v", open, err)
	}
	r.out["gh pr list"] = `[{"number":3,"headRefName":"review/a/1","files":[{"path":"actions/rules/approved/a/meta.md"}]},{"number":4,"headRefName":"feature","files":[]}]`
	open, err := openReviews(r)
	if err != nil || len(open) != 1 || open[0].Number != 3 {
		t.Fatalf("%+v %v", open, err)
	}
	if rule, ok := ruleOfFiles(open[0]); !ok || rule != "a" {
		t.Errorf("ruleOfFiles = %q %v", rule, ok)
	}
	if _, ok := ruleOfFiles(openReview{Files: []struct {
		Path string `json:"path"`
	}{{"README.md"}}}); ok {
		t.Error("a PR of no approved document has a rule")
	}
}
