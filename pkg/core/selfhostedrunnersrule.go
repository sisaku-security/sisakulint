package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// SelfHostedRunnersRule detects use of self-hosted runners which pose security risks
// in public repositories. Self-hosted runners can persist state between workflow runs,
// allowing attackers to execute arbitrary code via pull requests.
//
// References:
// - https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security
// - https://owasp.org/www-project-top-10-ci-cd-security-risks/
type SelfHostedRunnersRule struct {
	BaseRule
	currentJob *ast.Job
}

// NewSelfHostedRunnersRule creates a new rule for detecting self-hosted runner usage.
func NewSelfHostedRunnersRule() *SelfHostedRunnersRule {
	return &SelfHostedRunnersRule{
		BaseRule: BaseRule{
			RuleName: "self-hosted-runner",
			RuleDesc: "Detects use of self-hosted runners which may pose security risks in public repositories",
		},
	}
}

// VisitJobPre checks if the job uses self-hosted runners.
func (rule *SelfHostedRunnersRule) VisitJobPre(node *ast.Job) error {
	rule.currentJob = node

	if node.RunsOn == nil {
		return nil
	}

	runner := node.RunsOn

	// Check direct self-hosted label
	if rule.hasSelfHostedLabel(runner) {
		rule.reportSelfHostedUsage(node, "direct label specification")
		return nil
	}

	// Check runner group (groups are typically self-hosted)
	if runner.Group != nil && runner.Group.Value != "" {
		rule.reportRunnerGroupUsage(node, runner.Group.Value)
		return nil
	}

	// Check LabelsExpr - this can be either a static value like "self-hosted"
	// or a dynamic expression like "${{ matrix.runner }}"
	if runner.LabelsExpr != nil {
		expr := runner.LabelsExpr.Value
		// Check if it's a static self-hosted value (not a ${{ }} expression)
		if !strings.Contains(expr, "${{") {
			if strings.EqualFold(expr, "self-hosted") {
				rule.reportSelfHostedUsageWithPos(node, runner.LabelsExpr.Pos, "direct label specification")
				return nil
			}
		} else {
			// It's a dynamic expression - check for matrix references
			rule.checkLabelsExpression(node, expr)
		}
	}

	return nil
}

// VisitJobPost resets the current job reference.
func (rule *SelfHostedRunnersRule) VisitJobPost(node *ast.Job) error {
	// Check matrix strategy for self-hosted values
	if node.Strategy != nil && node.Strategy.Matrix != nil {
		rule.checkMatrixForSelfHosted(node)
	}

	rule.currentJob = nil
	return nil
}

// hasSelfHostedLabel checks if the runner labels include "self-hosted".
// According to GitHub docs, self-hosted is identified by the first label being "self-hosted".
func (rule *SelfHostedRunnersRule) hasSelfHostedLabel(runner *ast.Runner) bool {
	if len(runner.Labels) == 0 {
		return false
	}

	// Check if any label is "self-hosted"
	// GitHub recommends "self-hosted" as the first label for self-hosted runners
	for _, label := range runner.Labels {
		if label != nil && strings.EqualFold(label.Value, "self-hosted") {
			return true
		}
	}

	return false
}

// checkLabelsExpression checks if the runs-on expression might reference self-hosted runners.
func (rule *SelfHostedRunnersRule) checkLabelsExpression(job *ast.Job, expr string) {
	// Check if expression references matrix values that might contain self-hosted
	if strings.Contains(expr, "matrix.") && job.Strategy != nil && job.Strategy.Matrix != nil {
		rule.checkMatrixExpressionForSelfHosted(job, expr)
	}
}

// checkMatrixExpressionForSelfHosted checks if matrix values referenced in expression contain self-hosted.
func (rule *SelfHostedRunnersRule) checkMatrixExpressionForSelfHosted(job *ast.Job, expr string) {
	matrix := job.Strategy.Matrix

	// If the entire matrix is an expression, we can't statically analyze it
	if matrix.Expression != nil {
		return
	}

	// Check each matrix row for self-hosted values
	for rowName, row := range matrix.Rows {
		// Check if this row is referenced in the expression
		if !strings.Contains(expr, "matrix."+rowName) {
			continue
		}

		// If the row is an expression, we can't statically analyze it
		if row.Expression != nil {
			continue
		}

		// Check each value in the row
		for _, val := range row.Values {
			if rule.isSelfHostedValue(val) {
				rule.reportMatrixSelfHosted(job, rowName, val)
			}
		}
	}
}

// checkMatrixForSelfHosted checks the matrix definition for self-hosted runner values.
func (rule *SelfHostedRunnersRule) checkMatrixForSelfHosted(job *ast.Job) {
	matrix := job.Strategy.Matrix

	// If the entire matrix is an expression, we can't statically analyze it
	if matrix.Expression != nil {
		return
	}

	runner := job.RunsOn
	if runner == nil {
		return
	}

	// Only check if runs-on references matrix values
	if runner.LabelsExpr == nil {
		return
	}

	expr := runner.LabelsExpr.Value
	if !strings.Contains(expr, "matrix.") {
		return
	}

	// Already checked in checkLabelsExpression
}

// isSelfHostedValue checks if a raw YAML value represents "self-hosted".
func (rule *SelfHostedRunnersRule) isSelfHostedValue(val ast.RawYAMLValue) bool {
	switch v := val.(type) {
	case *ast.RawYAMLString:
		return strings.EqualFold(v.Value, "self-hosted")
	case *ast.RawYAMLArray:
		// Check if array contains self-hosted
		for _, elem := range v.Elems {
			if rule.isSelfHostedValue(elem) {
				return true
			}
		}
	}
	return false
}

// reportSelfHostedUsage reports a self-hosted runner usage error.
func (rule *SelfHostedRunnersRule) reportSelfHostedUsage(job *ast.Job, context string) {
	rule.reportSelfHostedUsageWithPos(job, job.RunsOn.Labels[0].Pos, context)
}

// reportSelfHostedUsageWithPos reports a self-hosted runner usage error with a custom position.
func (rule *SelfHostedRunnersRule) reportSelfHostedUsageWithPos(job *ast.Job, pos *ast.Position, context string) {
	rule.Errorf(
		pos,
		"job %q uses self-hosted runner (%s). Self-hosted runners are dangerous in public repositories "+
			"because they can persist state between workflow runs and allow arbitrary code execution from pull requests. "+
			"Consider using GitHub-hosted runners or ephemeral self-hosted runners. "+
			"See https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
		job.ID.Value,
		context,
	)
}

// reportRunnerGroupUsage reports a runner group usage warning.
func (rule *SelfHostedRunnersRule) reportRunnerGroupUsage(job *ast.Job, groupName string) {
	rule.Errorf(
		job.RunsOn.Group.Pos,
		"job %q uses runner group %q. Runner groups typically contain self-hosted runners, "+
			"which are dangerous in public repositories because they can persist state between workflow runs "+
			"and allow arbitrary code execution from pull requests. "+
			"Verify this group contains only ephemeral runners or consider using GitHub-hosted runners. "+
			"See https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
		job.ID.Value,
		groupName,
	)
}

// reportMatrixSelfHosted reports self-hosted runner in matrix values.
func (rule *SelfHostedRunnersRule) reportMatrixSelfHosted(job *ast.Job, rowName string, val ast.RawYAMLValue) {
	var pos *ast.Position
	switch v := val.(type) {
	case *ast.RawYAMLString:
		pos = v.Posi
	case *ast.RawYAMLArray:
		pos = v.Posi
	default:
		pos = job.Strategy.Matrix.Pos
	}

	rule.Errorf(
		pos,
		"job %q matrix.%s contains self-hosted runner. Self-hosted runners are dangerous in public repositories "+
			"because they can persist state between workflow runs and allow arbitrary code execution from pull requests. "+
			"Consider using GitHub-hosted runners or ephemeral self-hosted runners. "+
			"See https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
		job.ID.Value,
		rowName,
	)
}
