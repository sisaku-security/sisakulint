package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// ContainerEnvInjectionRule detects untrusted input in container.env and services.*.container.env
// fields. When an attacker controls these values, they can inject additional -e flags into the
// Docker CLI call, enabling container environment variable manipulation (CVE-2022-39321).
//
// It can be configured to check either privileged triggers (critical) or normal triggers (medium).
type ContainerEnvInjectionRule struct {
	BaseRule
	severityLevel   string // "critical" or "medium"
	checkPrivileged bool   // true = check privileged triggers only, false = check normal triggers only
	workflow        *ast.Workflow
}

// newContainerEnvInjectionRule creates a new container env injection rule.
func newContainerEnvInjectionRule(severityLevel string, checkPrivileged bool) *ContainerEnvInjectionRule {
	var desc string
	if checkPrivileged {
		desc = "Detects untrusted input in container.env or services.*.container.env in privileged workflow triggers (CVE-2022-39321). An attacker can inject additional Docker -e flags to manipulate container environment variables. See https://sisaku-security.github.io/lint/docs/rules/containerenvinjectioncritical/"
	} else {
		desc = "Detects untrusted input in container.env or services.*.container.env in normal workflow triggers (CVE-2022-39321). See https://sisaku-security.github.io/lint/docs/rules/containerenvinjectionmedium/"
	}

	return &ContainerEnvInjectionRule{
		BaseRule: BaseRule{
			RuleName: "container-env-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:   severityLevel,
		checkPrivileged: checkPrivileged,
	}
}

// ContainerEnvInjectionCriticalRule creates a rule for privileged workflow triggers.
func ContainerEnvInjectionCriticalRule() *ContainerEnvInjectionRule {
	return newContainerEnvInjectionRule("critical", true)
}

// ContainerEnvInjectionMediumRule creates a rule for normal workflow triggers.
func ContainerEnvInjectionMediumRule() *ContainerEnvInjectionRule {
	return newContainerEnvInjectionRule("medium", false)
}

// VisitWorkflowPre records the workflow for trigger analysis.
func (rule *ContainerEnvInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

// VisitJobPre checks container.env and services.*.container.env for untrusted input.
func (rule *ContainerEnvInjectionRule) VisitJobPre(node *ast.Job) error {
	isPrivileged := HasPrivilegedTriggers(rule.workflow)

	// Critical rule only fires on privileged triggers;
	// Medium rule only fires on non-privileged triggers (to avoid duplicate warnings).
	if rule.checkPrivileged != isPrivileged {
		return nil
	}

	// Check jobs.<job_id>.container.env
	if node.Container != nil && node.Container.Env != nil {
		rule.checkEnv(node.Container.Env, "container.env")
	}

	// Check jobs.<job_id>.services.<id>.container.env
	for svcName, svc := range node.Services {
		if svc == nil || svc.Container == nil || svc.Container.Env == nil {
			continue
		}
		rule.checkEnv(svc.Container.Env, "services."+svcName+".container.env")
	}

	return nil
}

// checkEnv inspects an Env node's variable values for untrusted expressions.
func (rule *ContainerEnvInjectionRule) checkEnv(env *ast.Env, location string) {
	if env.Vars == nil {
		return
	}

	for _, envVar := range env.Vars {
		if envVar == nil || envVar.Value == nil {
			continue
		}

		exprs := rule.extractAndParseExpressions(envVar.Value)
		for _, expr := range exprs {
			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) == 0 {
				continue
			}

			if rule.checkPrivileged {
				rule.Errorf(
					expr.pos,
					"container-env injection (critical): \"%s\" is potentially untrusted and used in %s with a privileged trigger. An attacker can manipulate container environment variables via Docker -e flag injection (CVE-2022-39321). Use a fixed value or validate the input. See https://sisaku-security.github.io/lint/docs/rules/containerenvinjectioncritical/",
					strings.Join(untrustedPaths, "\", \""),
					location,
				)
			} else {
				rule.Errorf(
					expr.pos,
					"container-env injection (medium): \"%s\" is potentially untrusted and used in %s. An attacker can manipulate container environment variables via Docker -e flag injection (CVE-2022-39321). See https://sisaku-security.github.io/lint/docs/rules/containerenvinjectionmedium/",
					strings.Join(untrustedPaths, "\", \""),
					location,
				)
			}
		}
	}
}

// extractAndParseExpressions extracts all ${{ }} expressions from a string value.
func (rule *ContainerEnvInjectionRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpression
	offset := 0

	for {
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := strings.TrimSpace(value[start+3 : start+endIdx])

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			var pos *ast.Position
			if str.Pos != nil {
				pos = &ast.Position{
					Line: str.Pos.Line + lineIdx,
					Col:  str.Pos.Col + col,
				}
			} else {
				pos = &ast.Position{Line: lineIdx + 1, Col: col + 1}
			}

			result = append(result, parsedExpression{
				raw:  exprContent,
				node: expr,
				pos:  pos,
			})
		}

		offset = start + endIdx + 2
	}

	return result
}

// parseExpression parses a single expression string.
func (rule *ContainerEnvInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput returns the untrusted paths found in an expression.
func (rule *ContainerEnvInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
		if strings.Contains(msg, "potentially untrusted") {
			if idx := strings.Index(msg, "\""); idx != -1 {
				endIdx := strings.Index(msg[idx+1:], "\"")
				if endIdx != -1 {
					paths = append(paths, msg[idx+1:idx+1+endIdx])
				}
			}
		}
	}

	return paths
}
