package analysis

import (
	"encoding/json"
	"errors"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CheckoutCode is what code a checkout brings into the workspace.
type CheckoutCode uint8

const (
	CodeBase    CheckoutCode = iota // the base's, or a ref of the repository written out
	CodePR                          // a commit, a ref or the fork of a pull request
	CodeUnknown                     // a value the tables cannot tell
)

var checkoutCodeNames = [...]string{"CodeBase", "CodePR", "CodeUnknown"}

func (t CheckoutCode) String() string { return checkoutCodeNames[t] }

// Guard is whether the release of actions/checkout refuses to bring a
// fork's code on pull_request_target and workflow_run.
type Guard uint8

const (
	GuardNone   Guard = iota // it does not: v1, a release before the guard, a branch, or allow-unsafe-pr-checkout
	GuardStatic              // it does: a major tag from v2, or a release from the guard on
	GuardSHA                 // pinned to a commit: it does if the commit has one of the guard's commits
)

var guardNames = [...]string{"GuardNone", "GuardStatic", "GuardSHA"}

func (g Guard) String() string { return guardNames[g] }

// Approval is what makes a person approve a run before it checks out the
// code of a pull request.
type Approval uint8

const (
	ApprovalNone        Approval = iota
	ApprovalLabel                // it runs only when a label is added (pull_request_target, labeled)
	ApprovalEnvironment          // its job has an environment, which may have required reviewers
)

// approvalNames are the values of $defs/approval of the schema of findings
// (actions/rules/schema/findings-v0.json), which the args of findings hold,
// and none, which they never hold.
var approvalNames = [...]string{"none", "label", "environment"}

func (a Approval) String() string { return approvalNames[a] }

// MarshalJSON writes a as the schema of findings names it
// (findings-v0.json, $defs/approval); ApprovalNone has no name there.
func (a Approval) MarshalJSON() ([]byte, error) {
	if a == ApprovalNone {
		return nil, errors.New("ApprovalNone is no approval")
	}
	return json.Marshal(a.String())
}

// CheckoutInput is an input of actions/checkout: the one a reference is in
// (ref, repository), or one that decides the credential it leaves
// (persist-credentials, path, token; actions/artifact).
type CheckoutInput uint8

const (
	CheckoutInputRef CheckoutInput = iota
	CheckoutInputRepository
	CheckoutInputPersistCredentials
	CheckoutInputPath
	CheckoutInputToken
)

var checkoutInputNames = [...]string{"ref", "repository", "persist-credentials", "path", "token"}

func (i CheckoutInput) String() string { return checkoutInputNames[i] }

// Guarded is whether the guard of actions/checkout covers the event e: on
// pull_request_target and workflow_run a release with the guard refuses a
// fork's code; on the other events it
// brings what it is asked.
func Guarded(e EventActivity) bool {
	return e.Name() == workflow.EventNamePullRequestTarget || e.Name() == workflow.EventNameWorkflowRun
}
