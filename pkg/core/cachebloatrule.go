package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// CacheBloatRule detects potential cache bloat issues when using actions/cache/restore and actions/cache/save
// without proper conditions to prevent cache accumulation.
//
// When both restore and save are used without proper conditions, the cache can grow indefinitely:
// 1. Old cache is restored
// 2. New build artifacts are added
// 3. Everything is saved back
//
// The recommended pattern is:
// - restore: skip on push events (github.event_name != 'push')
// - save: only run on push events (github.event_name == 'push')
//
// This ensures that:
// - On push to main/master: clean build creates fresh cache
// - On PR: cache is read-only, preventing bloat
type CacheBloatRule struct {
	BaseRule
	restoreSteps []*cacheStepInfo
	saveSteps    []*cacheStepInfo
}

type cacheStepInfo struct {
	step      *ast.Step
	condition string
}

// NewCacheBloatRule creates a new cache bloat detection rule.
func NewCacheBloatRule() *CacheBloatRule {
	return &CacheBloatRule{
		BaseRule: BaseRule{
			RuleName: "cache-bloat",
			RuleDesc: "Detects cache bloat risk when using actions/cache/restore and actions/cache/save without proper conditions",
		},
	}
}

// isCacheRestoreAction checks if the uses string is actions/cache/restore
func isCacheRestoreAction(uses string) bool {
	if uses == "" {
		return false
	}
	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}
	return actionName == "actions/cache/restore"
}

// isCacheSaveAction checks if the uses string is actions/cache/save
func isCacheSaveAction(uses string) bool {
	if uses == "" {
		return false
	}
	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}
	return actionName == "actions/cache/save"
}

// hasProperRestoreCondition checks if the condition properly skips on push events
func hasProperRestoreCondition(condition string) bool {
	if condition == "" {
		return false
	}

	// Patterns that indicate skipping on push:
	// - github.event_name != 'push'
	// - github.event_name != "push"
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`github\.event_name\s*!=\s*['"]push['"]`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(condition) {
			return true
		}
	}
	return false
}

// hasProperSaveCondition checks if the condition properly limits to push events
func hasProperSaveCondition(condition string) bool {
	if condition == "" {
		return false
	}

	// Patterns that indicate running only on push:
	// - github.event_name == 'push'
	// - github.event_name == "push"
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`github\.event_name\s*==\s*['"]push['"]`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(condition) {
			return true
		}
	}
	return false
}

func (rule *CacheBloatRule) VisitWorkflowPre(_ *ast.Workflow) error {
	return nil
}

func (rule *CacheBloatRule) VisitWorkflowPost(_ *ast.Workflow) error {
	return nil
}

func (rule *CacheBloatRule) VisitJobPre(_ *ast.Job) error {
	// Reset for each job
	rule.restoreSteps = nil
	rule.saveSteps = nil
	return nil
}

func (rule *CacheBloatRule) VisitJobPost(_ *ast.Job) error {
	// Check if both restore and save exist in this job
	if len(rule.restoreSteps) == 0 || len(rule.saveSteps) == 0 {
		// If only one type exists, no bloat risk from this pattern
		return nil
	}

	// Check each restore step for proper condition
	for _, info := range rule.restoreSteps {
		if !hasProperRestoreCondition(info.condition) {
			rule.Errorf(
				info.step.Pos,
				"cache bloat risk: actions/cache/restore should have condition to skip on push events. "+
					"Add 'if: github.event_name != 'push'' to prevent cache accumulation. "+
					"This ensures clean cache is built on push to main branch while PRs use read-only cache",
			)
			rule.AddAutoFixer(NewStepFixer(info.step, rule))
		}
	}

	// Check each save step for proper condition
	for _, info := range rule.saveSteps {
		if !hasProperSaveCondition(info.condition) {
			rule.Errorf(
				info.step.Pos,
				"cache bloat risk: actions/cache/save should have condition to run only on push events. "+
					"Add 'if: github.event_name == 'push'' to prevent cache accumulation. "+
					"This ensures only main branch builds write to cache while PRs are read-only",
			)
			rule.AddAutoFixer(NewStepFixer(info.step, rule))
		}
	}

	return nil
}

func (rule *CacheBloatRule) VisitStep(node *ast.Step) error {
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value
	condition := ""
	if node.If != nil {
		condition = node.If.Value
	}

	if isCacheRestoreAction(uses) {
		rule.restoreSteps = append(rule.restoreSteps, &cacheStepInfo{
			step:      node,
			condition: condition,
		})
	} else if isCacheSaveAction(uses) {
		rule.saveSteps = append(rule.saveSteps, &cacheStepInfo{
			step:      node,
			condition: condition,
		})
	}

	return nil
}

// FixStep implements auto-fix for cache bloat issues
func (rule *CacheBloatRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value
	var newCondition string

	if isCacheRestoreAction(uses) {
		newCondition = "github.event_name != 'push'"
	} else if isCacheSaveAction(uses) {
		newCondition = "github.event_name == 'push'"
	} else {
		return nil
	}

	return rule.addOrUpdateIfCondition(node, newCondition)
}

// addOrUpdateIfCondition adds or updates the if condition for a step
func (rule *CacheBloatRule) addOrUpdateIfCondition(node *ast.Step, newCondition string) error {
	stepNode := node.BaseNode
	if stepNode == nil {
		return nil
	}

	// Check if 'if' already exists
	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == "if" {
			// Append to existing condition
			existingCondition := val.Value
			if existingCondition != "" {
				val.Value = "(" + existingCondition + ") && " + newCondition
			} else {
				val.Value = newCondition
			}
			return nil
		}
	}

	// 'if' doesn't exist, add it after 'name' or at the beginning
	ifKeyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "if",
	}
	ifValNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: newCondition,
	}

	// Find the position to insert (after 'name' if exists, otherwise at start)
	insertPos := 0
	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		if key.Value == MainName {
			insertPos = i + 2
			break
		}
	}

	// Insert the new if condition
	newContent := make([]*yaml.Node, 0, len(stepNode.Content)+2)
	newContent = append(newContent, stepNode.Content[:insertPos]...)
	newContent = append(newContent, ifKeyNode, ifValNode)
	newContent = append(newContent, stepNode.Content[insertPos:]...)
	stepNode.Content = newContent

	return nil
}
