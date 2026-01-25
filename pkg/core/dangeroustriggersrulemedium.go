package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// DangerousTriggersMediumRule detects workflows using privileged triggers
// (pull_request_target, workflow_run, issue_comment, etc.) with only partial
// security mitigations. This is a medium security risk.
//
// References:
// - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
// - https://docs.zizmor.sh/audits/#dangerous-triggers
type DangerousTriggersMediumRule struct {
	BaseRule
	workflow *ast.Workflow
}

// NewDangerousTriggersMediumRule creates a new DangerousTriggersMediumRule instance.
func NewDangerousTriggersMediumRule() *DangerousTriggersMediumRule {
	return &DangerousTriggersMediumRule{
		BaseRule: BaseRule{
			RuleName: "dangerous-triggers-medium",
			RuleDesc: "Detects workflows using privileged triggers with only partial security mitigations. Consider adding more mitigations for defense in depth. See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		},
	}
}

// VisitWorkflowPre checks for privileged triggers with partial mitigations
func (rule *DangerousTriggersMediumRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node

	// Check if workflow has privileged triggers
	if !HasPrivilegedTriggers(node) {
		return nil
	}

	// Check mitigations
	status := CheckMitigations(node)

	// Only report if severity is medium (score = 1-2)
	if status.Severity() != SeverityMedium {
		return nil
	}

	// Get the privileged trigger names for the error message
	triggerNames := GetPrivilegedTriggerNames(node)
	triggerEvents := GetPrivilegedTriggerEvents(node)

	// Get found mitigations for the message
	foundMitigations := status.FoundMitigations()
	mitigationList := strings.Join(foundMitigations, ", ")

	// Generate error message
	triggerList := strings.Join(triggerNames, ", ")
	msg := fmt.Sprintf(
		"dangerous trigger (medium): workflow uses privileged trigger(s) [%s] with partial mitigations (%s). "+
			"Consider adding more mitigations for defense in depth: restrict permissions (permissions: read-all), "+
			"use environment protection, add label conditions, or check github.actor. "+
			"See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		triggerList,
		mitigationList,
	)

	// Report error at the position of the first privileged trigger
	pos := getEventPosition(triggerEvents, node)

	rule.Errorf(pos, "%s", msg)

	// Add auto-fixer if permissions are not already restricted
	if !status.HasPermissionsRestriction {
		rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
			return addEmptyPermissionsToWorkflow(node)
		}))
	}

	return nil
}
