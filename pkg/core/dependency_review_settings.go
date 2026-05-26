package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

const dependencyReviewSettingsRuleName = "dependency-review-settings"

// DependencyReviewSettingsRule checks settings for actions/dependency-review-action.
type DependencyReviewSettingsRule struct {
	BaseRule
	workflowPermissions *ast.Permissions
	currentPermissions  *ast.Permissions
}

func NewDependencyReviewSettingsRule() *DependencyReviewSettingsRule {
	return &DependencyReviewSettingsRule{
		BaseRule: BaseRule{
			RuleName: dependencyReviewSettingsRuleName,
			RuleDesc: "Checks actions/dependency-review-action settings for required permissions",
		},
	}
}

func (rule *DependencyReviewSettingsRule) VisitWorkflowPre(workflow *ast.Workflow) error {
	rule.workflowPermissions = workflow.Permissions
	rule.currentPermissions = workflow.Permissions
	return nil
}

func (rule *DependencyReviewSettingsRule) VisitJobPre(job *ast.Job) error {
	if job.Permissions != nil {
		rule.currentPermissions = job.Permissions
		return nil
	}
	rule.currentPermissions = rule.workflowPermissions
	return nil
}

func (rule *DependencyReviewSettingsRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil || !isDependencyReviewAction(action.Uses.Value) {
		return nil
	}

	input := action.Inputs["comment-summary-in-pr"]
	if input == nil || input.Value == nil {
		return nil
	}

	mode := strings.ToLower(strings.TrimSpace(input.Value.Value))
	if mode != "always" && mode != "on-failure" {
		return nil
	}

	if hasPullRequestsWrite(rule.currentPermissions) {
		return nil
	}

	pos := input.Value.Pos
	if pos == nil {
		pos = step.Pos
	}
	rule.Errorf(
		pos,
		"actions/dependency-review-action sets comment-summary-in-pr: %s, but effective permissions do not include pull-requests: write. Add pull-requests: write at the job permissions level or disable PR comments. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
		mode,
	)
	return nil
}

func isDependencyReviewAction(uses string) bool {
	uses = strings.ToLower(strings.TrimSpace(uses))
	action, _, ok := strings.Cut(uses, "@")
	return ok && action == "actions/dependency-review-action"
}

func hasPullRequestsWrite(permissions *ast.Permissions) bool {
	if permissions == nil {
		return false
	}
	if permissions.All != nil {
		return permissions.All.Value == "write-all"
	}
	scope := permissions.Scopes["pull-requests"]
	return scope != nil && scope.Value != nil && scope.Value.Value == "write"
}
