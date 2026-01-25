package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// PrivilegedTriggers contains the list of workflow triggers that grant elevated privileges.
// These triggers have write access to the repository or can access secrets, making them
// potentially dangerous when combined with untrusted input.
//
// References:
// - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
// - https://docs.zizmor.sh/audits/#dangerous-triggers
var PrivilegedTriggers = map[string]bool{
	"pull_request_target": true, // Has write access and secrets, triggered by untrusted PRs
	"workflow_run":        true, // Executes with elevated privileges after another workflow
	"issue_comment":       true, // Triggered by untrusted issue/PR comments
	"issues":              true, // Can be triggered by external users
	"discussion_comment":  true, // Triggered by untrusted discussion comments
}

// HasPrivilegedTriggers checks if a workflow has any privileged triggers.
// It returns true if any of the workflow's triggers are in the PrivilegedTriggers list.
//
// Example:
//
//	workflow := &ast.Workflow{
//	    On: []ast.Event{
//	        &ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
//	    },
//	}
//	if HasPrivilegedTriggers(workflow) {
//	    // Handle privileged workflow
//	}
func HasPrivilegedTriggers(workflow *ast.Workflow) bool {
	if workflow == nil || workflow.On == nil {
		return false
	}

	for _, event := range workflow.On {
		eventName := strings.ToLower(event.EventName())
		if PrivilegedTriggers[eventName] {
			return true
		}
	}

	return false
}

// GetPrivilegedTriggerNames returns a slice of privileged trigger names found in the workflow.
// Returns an empty slice if no privileged triggers are found.
//
// Example:
//
//	workflow := &ast.Workflow{
//	    On: []ast.Event{
//	        &ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
//	        &ast.WebhookEvent{Hook: &ast.String{Value: "workflow_run"}},
//	    },
//	}
//	triggers := GetPrivilegedTriggerNames(workflow)
//	// triggers = []string{"pull_request_target", "workflow_run"}
func GetPrivilegedTriggerNames(workflow *ast.Workflow) []string {
	if workflow == nil || workflow.On == nil {
		return nil
	}

	var triggers []string
	for _, event := range workflow.On {
		eventName := strings.ToLower(event.EventName())
		if PrivilegedTriggers[eventName] {
			triggers = append(triggers, eventName)
		}
	}

	return triggers
}

// GetPrivilegedTriggerEvents returns the Event objects for privileged triggers in the workflow.
// This is useful when you need access to the full event configuration (e.g., for position info).
//
// Example:
//
//	events := GetPrivilegedTriggerEvents(workflow)
//	for _, event := range events {
//	    pos := event.Pos() // Get position for error reporting
//	}
func GetPrivilegedTriggerEvents(workflow *ast.Workflow) []ast.Event {
	if workflow == nil || workflow.On == nil {
		return nil
	}

	var events []ast.Event
	for _, event := range workflow.On {
		eventName := strings.ToLower(event.EventName())
		if PrivilegedTriggers[eventName] {
			events = append(events, event)
		}
	}

	return events
}
