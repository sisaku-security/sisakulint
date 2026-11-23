package facts

import (
	"encoding/json"
	"testing"
)

// TestStepPathParallel: a step of a parallel group is
// jobs.<id>.steps[<n>].parallel[<m>]; an action has no groups.
func TestStepPathParallel(t *testing.T) {
	g, err := WorkflowGroupStep("build", 2, 0)
	if err != nil || g.String() != "jobs.build.steps[2].parallel[0]" {
		t.Fatalf("WorkflowGroupStep = %v, %v", g, err)
	}
	if p, err := ParseStepPath("jobs.build.steps[2].parallel[0]"); err != nil || p != g {
		t.Errorf("ParseStepPath = %v, %v", p, err)
	}
	for _, s := range []string{"runs.steps[0].parallel[0]", "jobs.build.steps[1].parallel[01]", "jobs.build.steps[1].parallel[-1]", "jobs.build.steps[1].parallel", "jobs.build.parallel[0]"} {
		if _, err := ParseStepPath(s); err == nil {
			t.Errorf("ParseStepPath(%q): no error", s)
		}
	}
	if _, err := WorkflowGroupStep("build", 1, -1); err == nil {
		t.Error("WorkflowGroupStep(-1): no error")
	}
	b, _ := json.Marshal(g)
	var back StepPath
	if err := json.Unmarshal(b, &back); err != nil || back != g {
		t.Errorf("round trip %s: %v, %v", b, back, err)
	}
}
