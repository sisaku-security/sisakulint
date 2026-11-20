package workflow

import "testing"

// TestParseRunnerLabelName: a label is not empty and has no white space
// around it; labels compare in any case.
func TestParseRunnerLabelName(t *testing.T) {
	for _, s := range []string{"", " ", " x", "x ", "\tx"} {
		if _, err := ParseRunnerLabelName(s); err == nil {
			t.Errorf("%q is a label", s)
		}
	}
	l, err := ParseRunnerLabelName("SELF-HOSTED")
	if err != nil || !l.Equal(SelfHostedLabel) || l.String() != "SELF-HOSTED" || l == SelfHostedLabel {
		t.Error(l, err)
	}
	if SelfHostedLabel.String() != "self-hosted" {
		t.Error(SelfHostedLabel)
	}
}

// TestRunsOnForm: how runs-on is written.
func TestRunsOnForm(t *testing.T) {
	for _, c := range []struct {
		runsOn string
		want   RunsOnForm
	}{
		{"x", RunsOnFormString},
		{"' x '", RunsOnFormString},
		{"[x, y]", RunsOnFormSequence},
		{"{group: g}", RunsOnFormMapping},
		{"{labels: x}", RunsOnFormMapping},
		{"{labels: [x]}", RunsOnFormMapping},
		{"${{ inputs.r }}", RunsOnFormString},
	} {
		j := oneJob(t, "    runs-on: "+c.runsOn+"\n    steps: [{run: a}]\n")
		if j.RunsOnForm != c.want {
			t.Errorf("%s: %v, want %v", c.runsOn, j.RunsOnForm, c.want)
		}
	}
}
