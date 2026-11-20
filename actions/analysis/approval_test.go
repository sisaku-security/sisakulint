package analysis

import (
	"slices"
	"testing"
)

// TestApprovalValues: the approvals the rules count are a label added on
// pull_request_target and an environment with required reviewers. The
// credential premise of the terms (the threat model assumes that no
// attacker holds a credential that can add a label to a pull request or
// approve a deployment) is what makes either an approval; an approval of
// another kind needs the owner of the threat model to decide whether the
// premise covers the credential that gives the approval, before a value is
// added here.
func TestApprovalValues(t *testing.T) {
	want := []string{"none", "label", "environment"}
	if !slices.Equal(approvalNames[:], want) {
		t.Errorf("approvals %v, want %v", approvalNames, want)
	}
	for i, a := range []Approval{ApprovalNone, ApprovalLabel, ApprovalEnvironment} {
		if int(a) != i {
			t.Errorf("%v is %d, want %d", a, a, i)
		}
	}
}
