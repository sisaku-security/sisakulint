package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

type envVarWithUntrustedInput struct {
	envVarName     string
	untrustedPaths []string
	pos            *ast.Position
}

func (rule *CodeInjectionRule) checkShellMetacharacterInjection(step *ast.Step, envVarsWithUntrusted []envVarWithUntrustedInput) {
	if step.Exec == nil || step.Exec.Kind() != ast.ExecKindRun {
		return
	}

	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return
	}

	script := run.Run.Value
	parser := shell.NewShellParser(script)

	for _, envVar := range envVarsWithUntrusted {
		usages := parser.FindEnvVarUsages(envVar.envVarName)

		for _, usage := range usages {
			if usage.IsUnsafeUsage() {
				reason := rule.getUnsafeUsageReason(usage)
				paths := strings.Join(envVar.untrustedPaths, "\", \"")

				if rule.checkPrivileged {
					rule.Errorf(
						run.Run.Pos,
						"code injection via shell metacharacters (critical): environment variable $%s contains untrusted input (\"%s\") and is %s. This can lead to command injection even when using environment variables. Use proper quoting: \"$%s\" or validate input before use. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						envVar.envVarName,
						paths,
						reason,
						envVar.envVarName,
					)
				} else {
					rule.Errorf(
						run.Run.Pos,
						"code injection via shell metacharacters (medium): environment variable $%s contains untrusted input (\"%s\") and is %s. Use proper quoting: \"$%s\" or validate input before use. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						envVar.envVarName,
						paths,
						reason,
						envVar.envVarName,
					)
				}
			}
		}
	}
}

func (rule *CodeInjectionRule) getUnsafeUsageReason(usage shell.ShellVarUsage) string {
	reasons := []string{}

	if !usage.IsQuoted {
		reasons = append(reasons, "used without double quotes (allows word splitting and glob expansion)")
	}

	if usage.InEval {
		reasons = append(reasons, "used inside eval (shell parses the value again)")
	}

	if usage.InShellCmd {
		reasons = append(reasons, "used inside sh -c or bash -c (creates nested shell parsing)")
	}

	if usage.InCmdSubst {
		reasons = append(reasons, "used inside command substitution ($() or backticks)")
	}

	if len(reasons) == 0 {
		return "used unsafely"
	}

	return strings.Join(reasons, "; ")
}

func (rule *CodeInjectionRule) extractEnvVarsWithUntrustedInput(step *ast.Step) []envVarWithUntrustedInput {
	var result []envVarWithUntrustedInput

	if step.Env == nil || step.Env.Vars == nil {
		return result
	}

	for _, envVar := range step.Env.Vars {
		if envVar.Value == nil || !envVar.Value.ContainsExpression() {
			continue
		}

		exprs := rule.extractAndParseExpressions(envVar.Value)
		var untrustedPaths []string

		for _, expr := range exprs {
			paths := rule.checkUntrustedInput(expr)
			untrustedPaths = append(untrustedPaths, paths...)
		}

		if len(untrustedPaths) > 0 {
			name := envVar.Name.Value
			result = append(result, envVarWithUntrustedInput{
				envVarName:     name,
				untrustedPaths: untrustedPaths,
				pos:            envVar.Value.Pos,
			})
		}
	}

	return result
}

func (rule *CodeInjectionRule) checkDangerousShellPatterns(step *ast.Step) {
	if step.Exec == nil || step.Exec.Kind() != ast.ExecKindRun {
		return
	}

	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return
	}

	script := run.Run.Value
	parser := shell.NewShellParser(script)

	if !parser.HasDangerousPattern() {
		return
	}

	patternType := parser.GetDangerousPatternType()
	exprs := rule.extractAndParseExpressions(run.Run)

	for _, expr := range exprs {
		untrustedPaths := rule.checkUntrustedInput(expr)
		if len(untrustedPaths) > 0 {
			paths := strings.Join(untrustedPaths, "\", \"")

			if rule.checkPrivileged {
				rule.Errorf(
					expr.pos,
					"code injection via %s (critical): \"%s\" is potentially untrusted and used with %s. Using %s with untrusted input is dangerous even inside quotes because the shell parses the content again. Consider using a safer approach or thorough input validation. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
					patternType,
					paths,
					patternType,
					patternType,
				)
			} else {
				rule.Errorf(
					expr.pos,
					"code injection via %s (medium): \"%s\" is potentially untrusted and used with %s. Consider using a safer approach or thorough input validation. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
					patternType,
					paths,
					patternType,
				)
			}
		}
	}

	envVarsWithUntrusted := rule.extractEnvVarsWithUntrustedInput(step)
	for _, envVar := range envVarsWithUntrusted {
		usages := parser.FindEnvVarUsages(envVar.envVarName)
		for _, usage := range usages {
			if usage.InEval || usage.InShellCmd {
				paths := strings.Join(envVar.untrustedPaths, "\", \"")

				if rule.checkPrivileged {
					rule.Errorf(
						run.Run.Pos,
						"code injection via %s (critical): environment variable $%s contains untrusted input (\"%s\") and is used with %s. Even quoted variables are dangerous inside %s because the shell parses the content again. Use thorough input validation or a safer approach. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						patternType,
						envVar.envVarName,
						paths,
						patternType,
						patternType,
					)
				} else {
					rule.Errorf(
						run.Run.Pos,
						"code injection via %s (medium): environment variable $%s contains untrusted input (\"%s\") and is used with %s. Use thorough input validation or a safer approach. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						patternType,
						envVar.envVarName,
						paths,
						patternType,
					)
				}
			}
		}
	}
}
