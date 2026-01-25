package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// DangerousTriggersCriticalRule detects workflows using privileged triggers
// (pull_request_target, workflow_run, issue_comment, etc.) without any
// security mitigations. This is a critical security risk.
//
// References:
// - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
// - https://docs.zizmor.sh/audits/#dangerous-triggers
type DangerousTriggersCriticalRule struct {
	BaseRule
	workflow *ast.Workflow
}

// NewDangerousTriggersCriticalRule creates a new DangerousTriggersCriticalRule instance.
func NewDangerousTriggersCriticalRule() *DangerousTriggersCriticalRule {
	return &DangerousTriggersCriticalRule{
		BaseRule: BaseRule{
			RuleName: "dangerous-triggers-critical",
			RuleDesc: "Detects workflows using privileged triggers without any security mitigations. These triggers grant elevated privileges (write access, secrets) that can be exploited by malicious actors. See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		},
	}
}

// VisitWorkflowPre checks for privileged triggers without mitigations
func (rule *DangerousTriggersCriticalRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node

	// Check if workflow has privileged triggers
	if !HasPrivilegedTriggers(node) {
		return nil
	}

	// Check mitigations
	status := CheckMitigations(node)

	// Only report if severity is critical (score = 0)
	if status.Severity() != SeverityCritical {
		return nil
	}

	// Get the privileged trigger names for the error message
	triggerNames := GetPrivilegedTriggerNames(node)
	triggerEvents := GetPrivilegedTriggerEvents(node)

	// Generate error message
	triggerList := strings.Join(triggerNames, ", ")
	msg := fmt.Sprintf(
		"dangerous trigger (critical): workflow uses privileged trigger(s) [%s] without any security mitigations. "+
			"These triggers grant write access and secrets access to potentially untrusted code. "+
			"Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), "+
			"use environment protection, add label conditions, or check github.actor. "+
			"See https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		triggerList,
	)

	// Report error at the position of the first privileged trigger
	pos := getEventPosition(triggerEvents, node)

	rule.Errorf(pos, "%s", msg)

	// Add auto-fixer to add permissions: {} to the workflow
	rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
		return addEmptyPermissionsToWorkflow(node)
	}))

	return nil
}

// getEventPosition returns the position of the first privileged trigger event,
// or falls back to the workflow name position if not available.
func getEventPosition(events []ast.Event, workflow *ast.Workflow) *ast.Position {
	for _, event := range events {
		// Try to get position from WebhookEvent
		if webhookEvent, ok := event.(*ast.WebhookEvent); ok && webhookEvent.Pos != nil {
			return webhookEvent.Pos
		}
	}

	// Fallback to workflow name position
	if workflow != nil && workflow.Name != nil {
		return workflow.Name.Pos
	}

	return nil
}

// addEmptyPermissionsToWorkflow adds permissions: {} to a workflow
func addEmptyPermissionsToWorkflow(workflow *ast.Workflow) error {
	if workflow == nil {
		return nil
	}

	// Update AST
	workflow.Permissions = &ast.Permissions{
		All: &ast.String{
			Value: "{}",
			Pos:   &ast.Position{Line: 1, Col: 1},
		},
	}

	// Update the YAML node if available
	if workflow.BaseNode != nil {
		return addPermissionsToYAMLNode(workflow.BaseNode)
	}

	return nil
}

// addPermissionsToYAMLNode adds permissions: {} to the YAML node
func addPermissionsToYAMLNode(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	// Check if permissions already exists
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 < len(node.Content) && node.Content[i].Value == "permissions" {
			// Already exists, don't add again
			return nil
		}
	}

	// Find position to insert (after 'on:' if possible, otherwise at start)
	insertIdx := 0
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "on" {
			insertIdx = i + 2
			break
		}
	}

	// Create permissions: {} node
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "permissions",
		Tag:   "!!str",
	}
	valueNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	// Insert at the appropriate position
	newContent := make([]*yaml.Node, 0, len(node.Content)+2)
	newContent = append(newContent, node.Content[:insertIdx]...)
	newContent = append(newContent, keyNode, valueNode)
	newContent = append(newContent, node.Content[insertIdx:]...)
	node.Content = newContent

	return nil
}
