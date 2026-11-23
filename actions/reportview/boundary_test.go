package reportview

import (
	"encoding/json"
	"testing"

	"github.com/gh-intel/sisakulint/actions/boundary"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func TestCatalogBoundary(t *testing.T) {
	b, err := buildBoundary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Grants) != len(boundary.Grants()) || len(b.Baselines) != len(boundary.Baselines()) || len(b.ChannelRows) != len(boundary.Channels()) {
		t.Errorf("rows %d %d %d", len(b.Grants), len(b.Baselines), len(b.ChannelRows))
	}
	pr, ok := b.Runs["pull_request fork"]
	if !ok {
		t.Fatalf("no run of pull_request fork: %v", keysOf(b.Runs))
	}
	if len(pr.Facts) == 0 || len(pr.Values) != pow3(len(pr.Facts)) {
		t.Errorf("pull_request fork: facts %v, %d values", pr.Facts, len(pr.Values))
	}
	read, ok := b.Roles["read"]
	if !ok || len(read.Values) != pow3(len(read.Facts)) {
		t.Errorf("read: %+v", read)
	}
	if _, ok := b.ChannelCells["commenter read"]; !ok {
		t.Errorf("no channel of commenter read")
	}
	if len(b.PathwayRows) != len(boundary.Pathways()) {
		t.Errorf("pathway rows %d", len(b.PathwayRows))
	}
	if _, ok := b.PathwayCells["artifact-reader none"]; !ok {
		t.Errorf("no pathway of artifact-reader none: %v", keysOf(b.PathwayCells))
	}
	if b.Crossings["true"]["false"] != boundary.CrossingByWorkflow || b.Crossings["false"]["true"] != boundary.CrossingByBaseline {
		t.Errorf("crossings %v", b.Crossings)
	}
	if len(b.RoleOrder) != 6 || b.RoleOrder[0] != boundary.RoleNone || b.RoleOrder[5] != boundary.RoleAdmin {
		t.Errorf("role order %v, want the least first", b.RoleOrder)
	}
	if len(b.Unreachable) == 0 || b.Unreachable[0] != "fork-pr-author repository" {
		t.Errorf("unreachable %v, want fork-pr-author repository", b.Unreachable)
	}
	if _, err := json.Marshal(b); err != nil {
		t.Fatal(err)
	}
}

func pow3(n int) int {
	p := 1
	for range n {
		p *= 3
	}
	return p
}

func keysOf[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestCatalogBoundaryHolds: the truth of each row for each set of answers
// of its facts is what lint.Eval gives, and a row that reads no fact holds.
func TestCatalogBoundaryHolds(t *testing.T) {
	b, err := buildBoundary(nil)
	if err != nil {
		t.Fatal(err)
	}
	noInputs := func(facts.InputPath) lint.LookupState { return lint.LookupUnknown }
	check := func(what string, c lint.Condition, h boundaryHolds) {
		qs := boundary.QueriesOf(c)
		if len(h.Holds) != pow3(len(qs)) || len(h.Facts) != len(qs) {
			t.Errorf("%s: facts %v, %d truths", what, h.Facts, len(h.Holds))
			return
		}
		for k, got := range h.Holds {
			if want := truthName(lint.Eval(c, answerOf(qs, k), noInputs)); got != want {
				t.Errorf("%s %q: %s, want %s", what, k, got, want)
			}
		}
	}
	for i, g := range boundary.Grants() {
		check("grant "+g.Event.String()+" "+g.Head.String(), g.Condition, b.Grants[i].boundaryHolds)
	}
	sawAlways := false
	for i, r := range boundary.Baselines() {
		check("baseline "+r.Role.String(), r.Condition, b.Baselines[i].boundaryHolds)
		if len(b.Baselines[i].Facts) == 0 && b.Baselines[i].Holds[""] == "true" {
			sawAlways = true
		}
	}
	if !sawAlways {
		t.Error("no baseline that reads no fact and holds under the key \"\"")
	}
	for i, c := range boundary.Channels() {
		check("channel "+c.Attacker.String()+" "+c.Role.String(), c.Condition, b.ChannelRows[i].boundaryHolds)
	}
}

// TestCatalogBoundaryHas: has, looked up by the holding of a gain, is the
// dimension of the gain, for every run and role and every key; and every
// gain, holding and crossing has its words.
func TestCatalogBoundaryHas(t *testing.T) {
	b, err := buildBoundary(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range b.Gains {
		if b.GainHoldings[g.String()] == boundary.HoldingUnset {
			t.Errorf("%s has no holding", g)
		}
	}
	for _, h := range boundary.Holdings() {
		if b.HoldingTexts[h.String()] == "" {
			t.Errorf("%s has no text", h)
		}
	}
	for _, c := range boundary.Crossings() {
		if b.CrossingTexts[c.String()] == "" {
			t.Errorf("%s has no text", c)
		}
	}
	cells := map[string]boundaryCell{}
	for k, c := range b.Runs {
		cells["run "+k] = c
	}
	for k, c := range b.Roles {
		cells["role "+k] = c
	}
	for name, c := range cells {
		for k, v := range c.Values {
			for _, g := range b.Gains {
				if got, want := v.Has[b.GainHoldings[g.String()].String()], v.Dims[g.String()]; got != want {
					t.Errorf("%s %q %s: has %s, dims %s", name, k, g, got, want)
				}
			}
		}
	}
	if v := b.Runs["pull_request fork"].Values; v == nil || v[keyOf(b.Runs["pull_request fork"].Facts, map[string]byte{"repo.public": 't'})].Ran != "true" {
		t.Error("the run of pull_request from a fork of a public repository does not run")
	}
}

// keyOf is the key of facts fs with the letters by, u for the rest.
func keyOf(fs []string, by map[string]byte) string {
	k := make([]byte, len(fs))
	for i, f := range fs {
		if l, ok := by[f]; ok {
			k[i] = l
		} else {
			k[i] = 'u'
		}
	}
	return string(k)
}

// TestCatalogPathwayCells: each pathway cell is what boundary answers, for
// every set of answers of its facts.
func TestCatalogPathwayCells(t *testing.T) {
	b, err := buildBoundary(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range boundary.Pathways() {
		k := p.Attacker.String() + " " + p.Role.String()
		c, ok := b.PathwayCells[k]
		if !ok {
			t.Errorf("no cell of %s", k)
			continue
		}
		qs := boundary.PathwayQueries(p.Attacker, p.Role)
		for _, key := range assignments(len(qs)) {
			u, _ := boundary.PathwayUsable(p.Attacker, p.Role, answerOf(qs, key))
			if got := c.Values[key].Usable; got != truthName(u) {
				t.Errorf("%s %s: usable %s, want %s", k, key, got, truthName(u))
			}
		}
	}
}

// TestCatalogRunGroups: the groups of runs are there for each set of
// holdings an actor with no event needs, and for nothing else.
func TestCatalogRunGroups(t *testing.T) {
	b, err := buildBoundary([]lint.Actor{
		{Attacker: lint.AttackerArtifactReader, Gains: []lint.Gain{lint.GainReadSecrets, lint.GainWriteWithToken}},
		{Attacker: lint.AttackerRepositoryReader, Gains: []lint.Gain{lint.GainUseRegistryAccount}},
		{Attacker: lint.AttackerCommenter, Events: []workflow.EventName{workflow.EventNameIssueComment}, Gains: []lint.Gain{lint.GainReadSecrets}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gs, ok := b.RunGroups["secrets,write-token"]
	if len(b.RunGroups) != 1 || !ok {
		t.Fatalf("groups %v", keysOf(b.RunGroups))
	}
	want := []string{"pull_request fork", "pull_request_review fork", "pull_request_review_comment fork"}
	if len(gs) != 2 || len(gs[0]) != len(want) {
		t.Fatalf("groups %v", gs)
	}
	for i, r := range want {
		if gs[0][i] != r {
			t.Errorf("group 0, run %d: %s, want %s", i, gs[0][i], r)
		}
	}
	if len(b.HoldingOrder) != len(boundary.Holdings()) || b.HoldingOrder[0] != boundary.HoldingSecrets {
		t.Errorf("holding order %v", b.HoldingOrder)
	}
}
