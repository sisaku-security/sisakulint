package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// UnmaskedSecretExposureRule detects unmasked secret exposure patterns in GitHub Actions workflows.
// When secrets are derived from other secrets using operations like fromJson(),
// the derived values are NOT automatically masked by GitHub Actions.
// This can lead to accidental exposure of sensitive information in workflow logs.
//
// See: https://codeql.github.com/codeql-query-help/actions/actions-unmasked-secret-exposure/
type UnmaskedSecretExposureRule struct {
	BaseRule
	currentStep   *ast.Step   // Track current step being visited (for auto-fix context)
	currentString *ast.String // Track current string being checked (for auto-fix context)
	currentJob    *ast.Job    // Track current job being visited (for auto-fix context)
}

// NewUnmaskedSecretExposureRule creates a new UnmaskedSecretExposureRule
func NewUnmaskedSecretExposureRule() *UnmaskedSecretExposureRule {
	return &UnmaskedSecretExposureRule{
		BaseRule: BaseRule{
			RuleName: "unmasked-secret-exposure",
			RuleDesc: "Detects unmasked secret exposure when secrets are derived using fromJson(). " +
				"Derived secret values are not automatically masked and may be exposed in logs. " +
				"See https://sisaku-security.github.io/lint/docs/rules/unmaskedsecretexposure/",
		},
	}
}

// VisitWorkflowPre checks workflow-level env for unmasked secret patterns
func (rule *UnmaskedSecretExposureRule) VisitWorkflowPre(node *ast.Workflow) error {
	if node.Env != nil {
		rule.checkEnv(node.Env)
	}
	return nil
}

// VisitJobPre visits each job and checks for unmasked secret exposure
func (rule *UnmaskedSecretExposureRule) VisitJobPre(node *ast.Job) error {
	rule.currentJob = node

	// Check job-level env
	if node.Env != nil {
		rule.checkEnv(node.Env)
	}

	// Check each step
	for _, step := range node.Steps {
		rule.checkStep(step)
	}

	return nil
}

// checkStep checks a single step for unmasked secret exposure patterns
func (rule *UnmaskedSecretExposureRule) checkStep(step *ast.Step) {
	rule.currentStep = step

	// Check step-level env
	if step.Env != nil {
		rule.checkEnv(step.Env)
	}

	if step.Exec == nil {
		return
	}

	switch exec := step.Exec.(type) {
	case *ast.ExecRun:
		// Check run: script
		if exec.Run != nil {
			rule.checkString(exec.Run)
		}
	case *ast.ExecAction:
		// Check action inputs (with:)
		for _, input := range exec.Inputs {
			if input != nil && input.Value != nil {
				rule.checkString(input.Value)
			}
		}
	}
}

// checkEnv checks environment variables for unmasked secret exposure
func (rule *UnmaskedSecretExposureRule) checkEnv(env *ast.Env) {
	if env.Expression != nil {
		rule.checkString(env.Expression)
	}

	for _, envVar := range env.Vars {
		if envVar.Value != nil {
			rule.checkString(envVar.Value)
		}
	}
}

// checkString extracts and checks expressions within a string
func (rule *UnmaskedSecretExposureRule) checkString(str *ast.String) {
	if str == nil {
		return
	}

	rule.currentString = str

	exprs := rule.extractAndParseExpressions(str)
	for _, expr := range exprs {
		rule.checkExpressionForUnmaskedSecret(expr)
	}
}

// extractAndParseExpressions extracts all ${{ }} expressions from a string and parses them
func (rule *UnmaskedSecretExposureRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
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

		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}
			if str.Literal {
				pos.Line++
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

// parseExpression parses a single expression string into an AST node
func (rule *UnmaskedSecretExposureRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkExpressionForUnmaskedSecret checks if an expression contains unmasked secret patterns
func (rule *UnmaskedSecretExposureRule) checkExpressionForUnmaskedSecret(expr parsedExpression) {
	// We need to find patterns like fromJson(secrets.XXX).yyy or fromJson(secrets.XXX)['yyy']
	// This means: a fromJson call on a secrets context, followed by property/index access

	// Check if the root expression or any part of it is a fromJson secrets access with dereferencing
	foundViolation := rule.checkNodeForFromJsonSecretsDeref(expr.node)

	if foundViolation {
		// Always report the error
		rule.reportUnmaskedSecretExposure(expr)

		// Add auto-fixer only if we have step context with ExecRun
		if rule.currentStep != nil {
			rule.addAutoFixer(expr)
		}
	}
}

// checkNodeForFromJsonSecretsDeref recursively checks if a node represents
// accessing a property/index of fromJson(secrets.XXX)
func (rule *UnmaskedSecretExposureRule) checkNodeForFromJsonSecretsDeref(node expressions.ExprNode) bool {
	switch n := node.(type) {
	case *expressions.ObjectDerefNode:
		// Check if this is accessing a property of fromJson(secrets.XXX)
		if rule.isDirectFromJsonSecretsCall(n.Receiver) {
			return true
		}
		// Check if the receiver is itself a deref of fromJson(secrets.XXX)
		// e.g., fromJson(secrets.X).a.b - we want to detect this at the outermost level
		return rule.checkNodeForFromJsonSecretsDeref(n.Receiver)

	case *expressions.IndexAccessNode:
		// Check if this is indexing into fromJson(secrets.XXX)
		if rule.isDirectFromJsonSecretsCall(n.Operand) {
			return true
		}
		// Check if the operand is itself accessing fromJson(secrets.XXX)
		return rule.checkNodeForFromJsonSecretsDeref(n.Operand)

	case *expressions.LogicalOpNode:
		// Check both sides of logical operations (&&, ||)
		return rule.checkNodeForFromJsonSecretsDeref(n.Left) ||
			rule.checkNodeForFromJsonSecretsDeref(n.Right)

	case *expressions.CompareOpNode:
		// Check both sides of comparisons
		return rule.checkNodeForFromJsonSecretsDeref(n.Left) ||
			rule.checkNodeForFromJsonSecretsDeref(n.Right)

	case *expressions.NotOpNode:
		return rule.checkNodeForFromJsonSecretsDeref(n.Operand)

	case *expressions.FuncCallNode:
		// Check arguments of function calls (e.g., toJson(fromJson(secrets.X).y))
		for _, arg := range n.Args {
			if rule.checkNodeForFromJsonSecretsDeref(arg) {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// isDirectFromJsonSecretsCall checks if a node is directly a fromJson(secrets.XXX) call
func (rule *UnmaskedSecretExposureRule) isDirectFromJsonSecretsCall(node expressions.ExprNode) bool {
	funcCall, ok := node.(*expressions.FuncCallNode)
	if !ok {
		return false
	}
	return rule.isFromJsonSecretsCall(funcCall)
}

// isFromJsonSecretsCall checks if a function call is fromJson(secrets.XXX)
func (rule *UnmaskedSecretExposureRule) isFromJsonSecretsCall(funcCall *expressions.FuncCallNode) bool {
	// Function names are case-insensitive
	if strings.ToLower(funcCall.Callee) != "fromjson" {
		return false
	}

	if len(funcCall.Args) != 1 {
		return false
	}

	// Check if the argument accesses the secrets context
	return rule.accessesSecretsContext(funcCall.Args[0])
}

// accessesSecretsContext checks if a node accesses the secrets context
func (rule *UnmaskedSecretExposureRule) accessesSecretsContext(node expressions.ExprNode) bool {
	switch n := node.(type) {
	case *expressions.VariableNode:
		return n.Name == "secrets"
	case *expressions.ObjectDerefNode:
		return rule.accessesSecretsContext(n.Receiver)
	case *expressions.IndexAccessNode:
		return rule.accessesSecretsContext(n.Operand)
	case *expressions.FuncCallNode:
		// Check if any argument accesses secrets (for nested functions like toJson(fromJson(secrets.X)))
		for _, arg := range n.Args {
			if rule.accessesSecretsContext(arg) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// reportUnmaskedSecretExposure reports an error for unmasked secret exposure
func (rule *UnmaskedSecretExposureRule) reportUnmaskedSecretExposure(expr parsedExpression) {
	rule.Errorf(
		expr.pos,
		"unmasked secret exposure: values derived from secrets using fromJson() are not automatically masked by GitHub Actions. "+
			"The expression '%s' may expose sensitive data in logs. "+
			"Consider using a separate secret for each value, or use '::add-mask::' to manually mask the derived value. "+
			"See https://sisaku-security.github.io/lint/docs/rules/unmaskedsecretexposure/",
		expr.raw,
	)
}

// addAutoFixer adds an auto-fixer that inserts add-mask command
func (rule *UnmaskedSecretExposureRule) addAutoFixer(expr parsedExpression) {
	step := rule.currentStep
	if step == nil || step.Exec == nil {
		return
	}

	// Only add fixer for ExecRun steps
	execRun, ok := step.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return
	}

	fixer := &unmaskedSecretExposureFixer{
		step:       step,
		expression: expr.raw,
		ruleName:   rule.RuleName,
	}

	rule.AddAutoFixer(NewStepFixer(step, fixer))
}

// unmaskedSecretExposureFixer fixes unmasked secret exposure by adding add-mask command
type unmaskedSecretExposureFixer struct {
	step       *ast.Step
	expression string // The expression containing fromJson(secrets.XXX).yyy
	ruleName   string
}

// RuleNames returns the rule name for this fixer
func (f *unmaskedSecretExposureFixer) RuleNames() string {
	return f.ruleName
}

// FixStep performs the auto-fix by prepending add-mask command to the run script
func (f *unmaskedSecretExposureFixer) FixStep(node *ast.Step) error {
	if node.Exec == nil {
		return nil
	}

	execRun, ok := node.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return nil
	}

	// Generate environment variable name from expression
	envVarName := f.generateEnvVarName()

	// Create add-mask command
	addMaskCommand := fmt.Sprintf("echo \"::add-mask::$%s\"", envVarName)

	// Check if add-mask for this variable already exists in the script
	originalScript := execRun.Run.Value
	if strings.Contains(originalScript, addMaskCommand) {
		// Add-mask already exists, don't duplicate
		return nil
	}

	// Insert add-mask command, respecting shebang if present
	if strings.HasPrefix(originalScript, "#!") {
		// Find the end of the first line (shebang)
		firstNewline := strings.Index(originalScript, "\n")
		if firstNewline == -1 {
			// Only shebang, no other content
			execRun.Run.Value = originalScript + "\n" + addMaskCommand
		} else {
			// Insert add-mask after shebang
			shebangLine := originalScript[:firstNewline]
			restOfScript := originalScript[firstNewline+1:]
			execRun.Run.Value = shebangLine + "\n" + addMaskCommand + "\n" + restOfScript
		}
	} else {
		// No shebang, prepend add-mask command to run script
		execRun.Run.Value = addMaskCommand + "\n" + originalScript
	}

	// Ensure env exists
	if node.Env == nil {
		node.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if node.Env.Vars == nil {
		node.Env.Vars = make(map[string]*ast.EnvVar)
	}

	// Add the expression as an environment variable if not already present
	envVarKey := strings.ToLower(envVarName)
	if _, exists := node.Env.Vars[envVarKey]; !exists {
		node.Env.Vars[envVarKey] = &ast.EnvVar{
			Name: &ast.String{Value: envVarName},
			Value: &ast.String{
				Value: fmt.Sprintf("${{ %s }}", f.expression),
			},
		}
	}

	// Update BaseNode if present
	if execRun.Run.BaseNode != nil {
		execRun.Run.BaseNode.Value = execRun.Run.Value
	}

	return nil
}

// generateEnvVarName generates an environment variable name from the expression
func (f *unmaskedSecretExposureFixer) generateEnvVarName() string {
	// Extract a meaningful name from the expression
	// e.g., "fromJson(secrets.AZURE_CREDENTIALS).clientId" -> "AZURE_CREDENTIALS_CLIENTID"

	expr := f.expression

	// Find the secret name
	secretStart := strings.Index(expr, "secrets.")
	if secretStart == -1 {
		return "MASKED_SECRET"
	}

	secretStart += len("secrets.")

	// Find end of secret name (until ')' or whitespace)
	secretEnd := secretStart
	for secretEnd < len(expr) {
		c := expr[secretEnd]
		if c == ')' || c == ' ' || c == '\t' {
			break
		}
		secretEnd++
	}

	secretName := expr[secretStart:secretEnd]

	// Find property name after the closing parenthesis
	propStart := strings.Index(expr, ").")
	if propStart != -1 {
		propStart += 2
		propEnd := propStart
		for propEnd < len(expr) {
			c := expr[propEnd]
			if !isIdentChar(c) {
				break
			}
			propEnd++
		}
		if propEnd > propStart {
			propName := expr[propStart:propEnd]
			return strings.ToUpper(secretName) + "_" + strings.ToUpper(propName)
		}
	}

	return strings.ToUpper(secretName) + "_DERIVED"
}

// isIdentChar checks if a character is valid in an identifier
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
