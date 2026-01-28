package core

import (
	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

type TimeoutMinutesRule struct {
	BaseRule
}

func TimeoutMinuteRule() *TimeoutMinutesRule {
	return &TimeoutMinutesRule{
		BaseRule: BaseRule{
			RuleName: "missing-timeout-minutes",
			RuleDesc: "This rule checks missing timeout-minutes in job level.",
		},
	}
}

func (rule *TimeoutMinutesRule) VisitJobPre(node *ast.Job) error {
	if node.TimeoutMinutes == nil {
		rule.Errorf(node.Pos,
			"timeout-minutes is not set for job %s; see https://sisaku-security.github.io/lint/docs/rules/timeoutminutesrule/ for more details.",
			node.ID.Value)
		rule.AddAutoFixer(NewJobFixer(node, rule))
	}
	return nil
}

func (rule *TimeoutMinutesRule) VisitStep(node *ast.Step) error {
	if node.TimeoutMinutes == nil {
		rule.Errorf(node.Pos,
			"timeout-minutes is not set for step %s; see https://sisaku-security.github.io/lint/docs/rules/timeoutminutesrule/ for more details.",
			node.String())
		rule.AddAutoFixer(NewStepFixer(node, rule))
	}
	return nil
}

func addTimeoutMinutes(node *yaml.Node, candidate1, candidate2 string) {
	// best effort to add timeout-minutes before run or uses
	appendKey := func(i int) {
		node.Content = append(node.Content[:i], append([]*yaml.Node{
			{
				Kind:  yaml.ScalarNode,
				Value: "timeout-minutes",
			},
			{
				Kind:  yaml.ScalarNode,
				Value: "5",
			},
		}, node.Content[i:]...)...)
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == candidate1 || node.Content[i].Value == candidate2 {
			appendKey(i)
			return
		}
	}
	// add timeout-minutes after candidate
	appendKey(len(node.Content))
}

func (rule *TimeoutMinutesRule) FixStep(node *ast.Step) error {
	addTimeoutMinutes(node.BaseNode, "run", "with")
	return nil
}

func (rule *TimeoutMinutesRule) FixJob(node *ast.Job) error {
	addTimeoutMinutes(node.BaseNode, "steps", "runs-on")
	return nil
}
