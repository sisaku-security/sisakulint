package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// Severity constants for dangerous triggers rules
const (
	SeverityCritical = "critical"
	SeverityMedium   = "medium"
)

// MitigationStatus represents the security mitigations applied to a workflow
// with privileged triggers. These mitigations help reduce the risk of security
// vulnerabilities when using dangerous workflow triggers like pull_request_target.
type MitigationStatus struct {
	// HasPermissionsRestriction indicates if workflow permissions are explicitly restricted
	// (not set to write-all). This is the most important mitigation. (+3 points)
	HasPermissionsRestriction bool

	// HasEnvironmentProtection indicates if the job uses environment protection rules.
	// Environment protection provides an additional approval gate. (+2 points)
	HasEnvironmentProtection bool

	// HasLabelCondition indicates if the workflow has label-based conditions
	// to restrict execution to approved PRs. (+1 point)
	HasLabelCondition bool

	// HasActorRestriction indicates if the workflow checks the actor
	// (e.g., github.actor) to restrict who can trigger it. (+1 point)
	HasActorRestriction bool

	// HasForkCheck indicates if the workflow checks for forks using
	// github.event.pull_request.head.repo.fork or similar. (+1 point)
	HasForkCheck bool
}

// Score calculates the total mitigation score based on the applied security measures.
// Higher scores indicate better security posture:
//   - 0: No mitigations (critical risk)
//   - 1-2: Minimal mitigations (medium risk)
//   - 3+: Adequate mitigations (acceptable risk)
//
// Example:
//
//	status := MitigationStatus{
//	    HasPermissionsRestriction: true,
//	    HasEnvironmentProtection: true,
//	}
//	score := status.Score() // returns 5
func (m *MitigationStatus) Score() int {
	score := 0

	if m.HasPermissionsRestriction {
		score += 3
	}
	if m.HasEnvironmentProtection {
		score += 2
	}
	if m.HasLabelCondition {
		score += 1
	}
	if m.HasActorRestriction {
		score += 1
	}
	if m.HasForkCheck {
		score += 1
	}

	return score
}

// Severity returns the severity level based on the mitigation score:
//   - "critical": No mitigations (score = 0)
//   - "medium": Minimal mitigations (score = 1-2)
//   - "": Adequate mitigations (score >= 3)
//
// Example:
//
//	status := MitigationStatus{} // no mitigations
//	severity := status.Severity() // returns "critical"
func (m *MitigationStatus) Severity() string {
	score := m.Score()

	if score == 0 {
		return SeverityCritical
	}
	if score <= 2 {
		return SeverityMedium
	}

	return ""
}

// FoundMitigations returns a list of mitigation names that are currently applied.
// This is useful for generating user-friendly messages about what security measures
// are in place.
//
// Example:
//
//	status := MitigationStatus{
//	    HasPermissionsRestriction: true,
//	    HasLabelCondition: true,
//	}
//	mitigations := status.FoundMitigations()
//	// returns []string{"permissions restriction", "label condition"}
func (m *MitigationStatus) FoundMitigations() []string {
	var mitigations []string

	if m.HasPermissionsRestriction {
		mitigations = append(mitigations, "permissions restriction")
	}
	if m.HasEnvironmentProtection {
		mitigations = append(mitigations, "environment protection")
	}
	if m.HasLabelCondition {
		mitigations = append(mitigations, "label condition")
	}
	if m.HasActorRestriction {
		mitigations = append(mitigations, "actor restriction")
	}
	if m.HasForkCheck {
		mitigations = append(mitigations, "fork check")
	}

	return mitigations
}

// CheckMitigations analyzes a workflow for security mitigations applied to
// privileged triggers. It examines:
//   - Workflow and job permissions
//   - Environment protection rules
//   - Job and step conditions for safety checks
//
// Returns a MitigationStatus indicating which security measures are present.
//
// Example:
//
//	workflow := &ast.Workflow{
//	    Permissions: &ast.Permissions{
//	        All: &ast.String{Value: "read-all"},
//	    },
//	    // ...
//	}
//	status := CheckMitigations(workflow)
//	// status.HasPermissionsRestriction will be true
func CheckMitigations(workflow *ast.Workflow) MitigationStatus {
	if workflow == nil {
		return MitigationStatus{}
	}

	status := MitigationStatus{}

	// Check workflow-level permissions
	if hasPermissionsRestriction(workflow.Permissions) {
		status.HasPermissionsRestriction = true
	}

	// Check job-level mitigations
	for _, job := range workflow.Jobs {
		if job == nil {
			continue
		}

		// Check job-level permissions
		if !status.HasPermissionsRestriction && hasPermissionsRestriction(job.Permissions) {
			status.HasPermissionsRestriction = true
		}

		// Check for environment protection
		if !status.HasEnvironmentProtection && job.Environment != nil && job.Environment.Name != nil {
			status.HasEnvironmentProtection = true
		}

		// Check job condition for mitigations
		if job.If != nil && job.If.Value != "" {
			checkConditionForMitigations(job.If.Value, &status)
		}

		// Check step conditions for mitigations
		for _, step := range job.Steps {
			if step == nil || step.If == nil || step.If.Value == "" {
				continue
			}
			checkConditionForMitigations(step.If.Value, &status)
		}
	}

	return status
}

// hasPermissionsRestriction checks if permissions are explicitly set and not write-all.
// Returns true if permissions restrict write access, false if write-all or not set.
func hasPermissionsRestriction(perms *ast.Permissions) bool {
	if perms == nil {
		return false
	}

	// If permissions.All is set
	if perms.All != nil && perms.All.Value != "" {
		value := strings.ToLower(perms.All.Value)
		// Only "read-all" or empty is a restriction (write-all is not)
		return value == "read-all" || value == "{}" || value == "none"
	}

	// If individual scopes are set, it's a restriction (not write-all)
	if len(perms.Scopes) > 0 {
		return true
	}

	return false
}

// checkConditionForMitigations checks a condition string for security-related patterns
// and updates the MitigationStatus accordingly. It looks for:
//   - Label checks: contains(github.event.pull_request.labels.*.name, 'safe-to-run')
//   - Actor restrictions: github.actor == 'trusted-user'
//   - Fork checks: github.event.pull_request.head.repo.fork == false
//
// The status parameter is modified in-place to reflect found mitigations.
func checkConditionForMitigations(condition string, status *MitigationStatus) {
	if condition == "" || status == nil {
		return
	}

	// Convert to lowercase for case-insensitive matching
	lowerCondition := strings.ToLower(condition)

	// Check for label-based conditions
	// Pattern: contains(...labels...) or github.event.pull_request.labels
	if !status.HasLabelCondition {
		if strings.Contains(lowerCondition, "labels") {
			status.HasLabelCondition = true
		}
	}

	// Check for actor restrictions
	// Pattern: github.actor, github.triggering_actor, etc.
	if !status.HasActorRestriction {
		if strings.Contains(lowerCondition, "github.actor") ||
			strings.Contains(lowerCondition, "github.triggering_actor") {
			status.HasActorRestriction = true
		}
	}

	// Check for fork checks
	// Pattern: github.event.pull_request.head.repo.fork
	if !status.HasForkCheck {
		if strings.Contains(lowerCondition, "fork") {
			status.HasForkCheck = true
		}
	}
}
