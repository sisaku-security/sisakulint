package lint

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/internal/corpus"
)

// TestCorpus enumerates each repository of yaml/corpus (real-world, org,
// sisakuintel and labeler-token) and runs a rule that reports every step, confirmed, and one that
// reports every step on a fact nobody knows. Nothing may panic or break the
// contract, and the report must fit its schema. Unless ACTIONS_CORPUS=full,
// one repository in seven.
func TestCorpus(t *testing.T) {
	var repos []string
	for _, group := range []string{"real-world", "org", "sisakuintel", "labeler-token"} {
		dir := filepath.Join(corpus.Dir(t), "files", group)
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() {
				repos = append(repos, filepath.Join(dir, e.Name()))
			}
		}
	}
	if !corpus.Full() {
		var some []string
		for i, r := range repos {
			if i%7 == 0 {
				some = append(some, r)
			}
		}
		repos = some
	}
	stepsOf := func(c *RuleContext) []workflow.Step {
		if c.action != nil {
			return c.action.Runs.Value.Steps.Value.Items
		}
		return steps(c)
	}
	all := meta("every-step")
	all.Targets = []InputKind{InputKindWorkflow, InputKindActionMetadata}
	cond := meta("cond-step")
	cond.Targets = all.Targets
	cond = asking(cond, facts.KindTestFlag)
	rules := []Rule{
		testRule{meta: all, check: func(_ context.Context, c *RuleContext) error {
			for _, s := range stepsOf(c) {
				c.Report(FindingDraft{Args: said("a step"), Location: At(c.input, s.Base), Anchor: s.Name.Value.Text()})
			}
			return nil
		}},
		testRule{meta: cond, check: func(_ context.Context, c *RuleContext) error {
			for _, s := range stepsOf(c) {
				q, _ := FactEq(facts.TestFlag{Name: "f"}, true)
				c.Report(FindingDraft{Args: said("a step, maybe"), Location: At(c.input, s.Base), Anchor: s.Name.Value.Text(), Condition: &q})
			}
			return nil
		}},
	}
	reg, err := newRegistry(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	s := schemas(t)
	for _, repo := range repos {
		t.Run(filepath.Base(repo), func(t *testing.T) {
			in, err := Enumerate(os.DirFS(repo))
			if err != nil {
				t.Fatal(err)
			}
			rep := Run(context.Background(), in, reg, mapResolver{})
			for _, e := range rep.Errors {
				t.Errorf("%s %s: %s", e.Rule, e.Input, e.Message)
			}
			b, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate("report-v0.json", "#", b); err != nil {
				t.Errorf("the report does not fit report-v0.json: %v", err)
			}
		})
	}
}
