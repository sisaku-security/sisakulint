package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

// CachePoisoningRule detects potential cache poisoning vulnerabilities in GitHub Actions workflows.
// It checks for:
// 1. Indirect cache poisoning: Untrusted triggers + unsafe checkout + cache actions
// 2. Direct cache poisoning: Untrusted input in cache key/restore-keys/path (any trigger)
type CachePoisoningRule struct {
	BaseRule
	unsafeTriggers      []string
	checkoutUnsafeRef   bool
	unsafeCheckoutStep  *ast.Step
	autoFixerRegistered bool
	directCacheFixSteps []*directCacheFixInfo
}

// directCacheFixInfo stores information needed for auto-fixing direct cache poisoning
type directCacheFixInfo struct {
	step      *ast.Step
	inputName string // "key", "restore-keys", or "path"
	expr      string // the untrusted expression
}

// NewCachePoisoningRule creates a new cache poisoning detection rule.
func NewCachePoisoningRule() *CachePoisoningRule {
	return &CachePoisoningRule{
		BaseRule: BaseRule{
			RuleName: "cache-poisoning",
			RuleDesc: "Detects potential cache poisoning vulnerabilities when using cache with untrusted triggers or untrusted inputs in cache configuration",
		},
		directCacheFixSteps: make([]*directCacheFixInfo, 0),
	}
}

func isCacheAction(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName == "actions/cache" {
		return true
	}

	if strings.HasPrefix(actionName, "actions/setup-") {
		if cacheInput, ok := inputs["cache"]; ok && cacheInput != nil {
			if cacheInput.Value != nil && cacheInput.Value.Value != "" && cacheInput.Value.Value != ExprFalseValue {
				return true
			}
		}
	}

	return false
}

func (rule *CachePoisoningRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.unsafeTriggers = nil
	rule.directCacheFixSteps = make([]*directCacheFixInfo, 0)

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil && IsUnsafeTrigger(e.Hook.Value) {
				rule.unsafeTriggers = append(rule.unsafeTriggers, e.Hook.Value)
			}
		}
	}

	return nil
}

func (rule *CachePoisoningRule) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

func (rule *CachePoisoningRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutUnsafeRef = false
	rule.unsafeCheckoutStep = nil
	rule.autoFixerRegistered = false
	return nil
}

func (rule *CachePoisoningRule) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *CachePoisoningRule) VisitStep(node *ast.Step) error {
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	// Check for checkout with unsafe ref (only with unsafe triggers)
	if actionName == "actions/checkout" && len(rule.unsafeTriggers) > 0 {
		if refInput, ok := action.Inputs["ref"]; ok && refInput != nil && refInput.Value != nil {
			if IsUnsafeCheckoutRef(refInput.Value.Value) {
				rule.checkoutUnsafeRef = true
				rule.unsafeCheckoutStep = node
			} else {
				// Safe checkout resets the unsafe state
				// This handles the case where an unsafe checkout is followed by a safe one
				rule.checkoutUnsafeRef = false
				rule.unsafeCheckoutStep = nil
			}
		} else {
			// Checkout without ref (defaults to base branch) is safe
			rule.checkoutUnsafeRef = false
			rule.unsafeCheckoutStep = nil
		}
		return nil
	}

	// Check for direct cache poisoning: untrusted input in cache key/restore-keys/path
	// This applies to any trigger (including pull_request, push, etc.)
	if actionName == "actions/cache" {
		rule.checkDirectCachePoisoning(node, action)
	}

	// Check for indirect cache poisoning (unsafe checkout + cache action)
	// This only applies with unsafe triggers
	if len(rule.unsafeTriggers) > 0 && rule.checkoutUnsafeRef && isCacheAction(uses, action.Inputs) {
		triggers := strings.Join(rule.unsafeTriggers, ", ")
		rule.Errorf(
			node.Pos,
			"cache poisoning risk: '%s' used after checking out untrusted PR code (triggers: %s). Validate cached content or scope cache to PR level",
			uses,
			triggers,
		)
		if rule.unsafeCheckoutStep != nil && !rule.autoFixerRegistered {
			rule.AddAutoFixer(NewStepFixer(rule.unsafeCheckoutStep, rule))
			rule.autoFixerRegistered = true
		}
	}

	return nil
}

// checkDirectCachePoisoning checks for untrusted inputs in cache key/restore-keys/path
func (rule *CachePoisoningRule) checkDirectCachePoisoning(node *ast.Step, action *ast.ExecAction) {
	// Check key input
	if keyInput, ok := action.Inputs["key"]; ok && keyInput != nil && keyInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "key", keyInput.Value)
	}

	// Check restore-keys input
	if restoreKeysInput, ok := action.Inputs["restore-keys"]; ok && restoreKeysInput != nil && restoreKeysInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "restore-keys", restoreKeysInput.Value)
	}

	// Check path input
	if pathInput, ok := action.Inputs["path"]; ok && pathInput != nil && pathInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "path", pathInput.Value)
	}
}

// checkCacheInputForUntrustedExprs checks a cache input value for untrusted expressions
func (rule *CachePoisoningRule) checkCacheInputForUntrustedExprs(node *ast.Step, inputName string, inputValue *ast.String) {
	if inputValue == nil {
		return
	}

	// Extract and parse all expressions from the input value
	exprs := rule.extractAndParseExpressions(inputValue)
	for _, expr := range exprs {
		untrustedPaths := rule.checkUntrustedInput(expr)
		if len(untrustedPaths) > 0 {
			// Report the vulnerability
			rule.Errorf(
				expr.pos,
				"cache poisoning via untrusted input: '%s' in cache %s is potentially untrusted. "+
					"An attacker can control the cache key to poison the cache. "+
					"Use trusted inputs like github.sha, hashFiles(), or static values instead",
				strings.Join(untrustedPaths, "', '"),
				inputName,
			)

			// Register auto-fixer for this step
			rule.directCacheFixSteps = append(rule.directCacheFixSteps, &directCacheFixInfo{
				step:      node,
				inputName: inputName,
				expr:      expr.raw,
			})
			rule.AddAutoFixer(NewStepFixer(node, rule))
		}
	}
}

// parsedExpressionCache represents a parsed expression with its position and AST node
type parsedExpressionCache struct {
	raw  string               // Original expression content
	node expressions.ExprNode // Parsed AST node
	pos  *ast.Position        // Position in source
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *CachePoisoningRule) extractAndParseExpressions(str *ast.String) []parsedExpressionCache {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpressionCache
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

			result = append(result, parsedExpressionCache{
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
func (rule *CachePoisoningRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *CachePoisoningRule) checkUntrustedInput(expr parsedExpressionCache) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
		if strings.Contains(msg, "potentially untrusted") {
			if idx := strings.Index(msg, "\""); idx != -1 {
				endIdx := strings.Index(msg[idx+1:], "\"")
				if endIdx != -1 {
					path := msg[idx+1 : idx+1+endIdx]
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

func (rule *CachePoisoningRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}

	// Check if this is an indirect cache poisoning fix (unsafe checkout)
	if node == rule.unsafeCheckoutStep {
		return RemoveRefFromWith(node.BaseNode)
	}

	// Check if this is a direct cache poisoning fix (untrusted input in cache config)
	for _, fixInfo := range rule.directCacheFixSteps {
		if fixInfo.step == node {
			return rule.fixDirectCachePoisoning(node, fixInfo)
		}
	}

	return nil
}

// fixDirectCachePoisoning fixes direct cache poisoning by suggesting safe alternatives
func (rule *CachePoisoningRule) fixDirectCachePoisoning(node *ast.Step, fixInfo *directCacheFixInfo) error {
	// For key/restore-keys, replace untrusted input with github.sha or hashFiles()
	// For path, we cannot safely auto-fix - just add a comment

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	switch fixInfo.inputName {
	case "key", "restore-keys":
		// Replace the untrusted expression with github.sha
		return rule.replaceUntrustedExprInCacheInput(node.BaseNode, fixInfo.inputName, fixInfo.expr)
	case SBOMPath:
		// For path, we cannot safely auto-fix as it depends on the project structure
		// The warning is sufficient to alert users
		return nil
	}

	return nil
}

// replaceUntrustedExprInCacheInput replaces an untrusted expression in cache input with github.sha
func (rule *CachePoisoningRule) replaceUntrustedExprInCacheInput(stepNode *yaml.Node, inputName string, untrustedExpr string) error {
	if stepNode == nil {
		return nil
	}

	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == SBOMWith && val.Kind == yaml.MappingNode {
			for j := 0; j < len(val.Content); j += 2 {
				if j+1 >= len(val.Content) {
					break
				}
				withKey := val.Content[j]
				withVal := val.Content[j+1]

				if withKey.Value == inputName {
					// Replace the untrusted expression with github.sha
					oldValue := withVal.Value
					newValue := strings.ReplaceAll(
						oldValue,
						fmt.Sprintf("${{ %s }}", untrustedExpr),
						"${{ github.sha }}",
					)
					newValue = strings.ReplaceAll(
						newValue,
						fmt.Sprintf("${{%s}}", untrustedExpr),
						"${{ github.sha }}",
					)
					withVal.Value = newValue
					return nil
				}
			}
		}
	}
	return nil
}
