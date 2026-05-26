package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

const dependencyReviewSettingsRuleName = "dependency-review-settings"

const dependencyReviewLargeAllowListThreshold = 5

var dependencyReviewGHSARe = regexp.MustCompile(`(?i)\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b`)

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
			RuleDesc: "Checks actions/dependency-review-action security gate settings and required permissions",
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

	rule.checkSecurityGateSettings(step, action)
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

func (rule *DependencyReviewSettingsRule) checkSecurityGateSettings(step *ast.Step, action *ast.ExecAction) {
	hasConfigFile := !dependencyReviewInputMissing(action, "config-file")
	vulnerabilityDisabled := false
	licenseDisabled := false

	if dependencyReviewInputEquals(action, "warn-only", "true") {
		rule.Errorf(
			dependencyReviewInputPos(step, action, "warn-only"),
			"(warning) actions/dependency-review-action sets warn-only: true, so dependency review findings will not fail the workflow. Disable warn-only for an enforcing security gate. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
		)
	}

	if value, ok := dependencyReviewDisabledInputValue(action, "vulnerability-check"); ok {
		vulnerabilityDisabled = true
		rule.Errorf(
			dependencyReviewInputPos(step, action, "vulnerability-check"),
			"(warning) actions/dependency-review-action sets vulnerability-check: %s, so vulnerable dependencies will not be checked. Enable vulnerability-check for an enforcing security gate. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
			value,
		)
	}

	if value, ok := dependencyReviewDisabledInputValue(action, "license-check"); ok {
		licenseDisabled = true
		rule.Errorf(
			dependencyReviewInputPos(step, action, "license-check"),
			"(info) actions/dependency-review-action sets license-check: %s. Enable license-check when license policy enforcement is expected. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
			value,
		)
	}

	if !hasConfigFile && !vulnerabilityDisabled && dependencyReviewInputMissing(action, "fail-on-severity") {
		rule.Errorf(
			dependencyReviewInputPos(step, action, "fail-on-severity"),
			"(info) actions/dependency-review-action does not set fail-on-severity. Set an explicit vulnerability severity threshold for the dependency review gate. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
		)
	}

	if !hasConfigFile && !vulnerabilityDisabled && dependencyReviewInputMissing(action, "fail-on-scopes") {
		rule.Errorf(
			dependencyReviewInputPos(step, action, "fail-on-scopes"),
			"(info) actions/dependency-review-action does not set fail-on-scopes. Set explicit dependency scopes for the dependency review gate. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
		)
	}

	if !hasConfigFile && !licenseDisabled && dependencyReviewInputMissing(action, "allow-licenses") && dependencyReviewInputMissing(action, "deny-licenses") {
		rule.Errorf(
			step.Pos,
			"(info) actions/dependency-review-action does not define a license policy with allow-licenses or deny-licenses. Configure one of them when license review is expected. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
		)
	}

	if value, ok := dependencyReviewScalarInput(action, "allow-ghsas"); ok && !dependencyReviewHasExpression(value) {
		count := len(dependencyReviewGHSARe.FindAllString(value, -1))
		if count >= dependencyReviewLargeAllowListThreshold {
			rule.Errorf(
				dependencyReviewInputPos(step, action, "allow-ghsas"),
				"(warning) actions/dependency-review-action allows %d GHSA advisories via allow-ghsas. A large vulnerability allow-list can weaken the dependency review gate. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
				count,
			)
		}
	}

	if value, ok := dependencyReviewScalarInput(action, "allow-dependencies-licenses"); ok && !dependencyReviewHasExpression(value) {
		count := countDependencyReviewListItems(value)
		if count >= dependencyReviewLargeAllowListThreshold {
			rule.Errorf(
				dependencyReviewInputPos(step, action, "allow-dependencies-licenses"),
				"(info) actions/dependency-review-action allows %d dependency/license exceptions via allow-dependencies-licenses. Large exception lists can make license checks ineffective. See https://sisaku-security.github.io/lint/docs/rules/dependencyreviewsettings/",
				count,
			)
		}
	}
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

func dependencyReviewInputEquals(action *ast.ExecAction, name string, want string) bool {
	value, ok := dependencyReviewScalarInput(action, name)
	if !ok || dependencyReviewHasExpression(value) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(value), want)
}

func dependencyReviewDisabledInputValue(action *ast.ExecAction, name string) (string, bool) {
	value, ok := dependencyReviewScalarInput(action, name)
	if !ok || dependencyReviewHasExpression(value) {
		return "", false
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "false" || normalized == "disable" {
		return normalized, true
	}
	return "", false
}

func dependencyReviewInputMissing(action *ast.ExecAction, name string) bool {
	value, ok := dependencyReviewScalarInput(action, name)
	return !ok || strings.TrimSpace(value) == ""
}

func dependencyReviewScalarInput(action *ast.ExecAction, name string) (string, bool) {
	if action == nil {
		return "", false
	}
	input := action.Inputs[strings.ToLower(name)]
	if input == nil || input.Value == nil {
		return "", false
	}
	return input.Value.Value, true
}

func dependencyReviewInputPos(step *ast.Step, action *ast.ExecAction, name string) *ast.Position {
	if action != nil {
		if input := action.Inputs[strings.ToLower(name)]; input != nil && input.Value != nil && input.Value.Pos != nil {
			return input.Value.Pos
		}
	}
	if step != nil {
		return step.Pos
	}
	return nil
}

func countDependencyReviewListItems(value string) int {
	count := 0
	for _, item := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		if strings.TrimSpace(item) != "" {
			count++
		}
	}
	return count
}

func dependencyReviewHasExpression(value string) bool {
	return strings.Contains(value, "${{")
}
