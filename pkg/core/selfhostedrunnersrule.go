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

func (rule *SelfHostedRunnersRule) VisitJobPre(node *ast.Job) error {
	rule.currentJob = node
	if node.RunsOn == nil {
		return nil
	}

	runner := node.RunsOn

	if rule.hasSelfHostedLabel(runner) {
		rule.reportSelfHostedUsage(node, "direct label specification")
		return nil
	}

	if runner.Group != nil && runner.Group.Value != "" {
		rule.reportRunnerGroupUsage(node, runner.Group.Value)
		return nil
	}

	if runner.LabelsExpr != nil {
		expr := runner.LabelsExpr.Value
		if !strings.Contains(expr, "${{") {
			if strings.EqualFold(expr, "self-hosted") {
				rule.reportSelfHostedUsageWithPos(node, runner.LabelsExpr.Pos, "direct label specification")
				return nil
			}
		} else {
			rule.checkLabelsExpression(node, expr)
		}
	}

	return nil
}

func (rule *SelfHostedRunnersRule) VisitJobPost(node *ast.Job) error {
	rule.currentJob = nil
	return nil
}

func (rule *SelfHostedRunnersRule) hasSelfHostedLabel(runner *ast.Runner) bool {
	for _, label := range runner.Labels {
		if label != nil && strings.EqualFold(label.Value, "self-hosted") {
			return true
		}
	}
	return false
}

func (rule *SelfHostedRunnersRule) checkLabelsExpression(job *ast.Job, expr string) {
	if strings.Contains(expr, "matrix.") && job.Strategy != nil && job.Strategy.Matrix != nil {
		rule.checkMatrixExpressionForSelfHosted(job, expr)
	}
}

func (rule *SelfHostedRunnersRule) checkMatrixExpressionForSelfHosted(job *ast.Job, expr string) {
	matrix := job.Strategy.Matrix
	if matrix.Expression != nil {
		return
	}

	for rowName, row := range matrix.Rows {
		if !strings.Contains(expr, "matrix."+rowName) {
			continue
		}
		if row.Expression != nil {
			continue
		}
		for _, val := range row.Values {
			if rule.isSelfHostedValue(val) {
				rule.reportMatrixSelfHosted(job, rowName, val)
			}
		}
	}
}

func (rule *SelfHostedRunnersRule) isSelfHostedValue(val ast.RawYAMLValue) bool {
	switch v := val.(type) {
	case *ast.RawYAMLString:
		return strings.EqualFold(v.Value, "self-hosted")
	case *ast.RawYAMLArray:
		for _, elem := range v.Elems {
			if rule.isSelfHostedValue(elem) {
				return true
			}
		}
	}
	return false
}

func (rule *SelfHostedRunnersRule) reportSelfHostedUsage(job *ast.Job, context string) {
	rule.reportSelfHostedUsageWithPos(job, job.RunsOn.Labels[0].Pos, context)
}

func (rule *SelfHostedRunnersRule) reportSelfHostedUsageWithPos(job *ast.Job, pos *ast.Position, context string) {
	rule.Errorf(
		pos,
		"job %q uses self-hosted runner (%s). Self-hosted runners are dangerous in public repositories "+
			"because they can persist state between workflow runs and allow arbitrary code execution from pull requests. "+
			"Consider using GitHub-hosted runners or ephemeral self-hosted runners. "+
			"See https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/",
		job.ID.Value,
		context,
	)
}

func (rule *SelfHostedRunnersRule) reportRunnerGroupUsage(job *ast.Job, groupName string) {
	rule.Errorf(
		job.RunsOn.Group.Pos,
		"job %q uses runner group %q. Runner groups typically contain self-hosted runners, "+
			"which are dangerous in public repositories because they can persist state between workflow runs "+
			"and allow arbitrary code execution from pull requests. "+
			"Verify this group contains only ephemeral runners or consider using GitHub-hosted runners. "+
			"See https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/",
		job.ID.Value,
		groupName,
	)
}

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
			"See https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/",
		job.ID.Value,
		rowName,
	)
}
