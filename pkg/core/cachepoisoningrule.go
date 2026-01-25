package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// CachePoisoningRule detects potential cache poisoning vulnerabilities in GitHub Actions workflows.
// It checks for:
// 1. Indirect cache poisoning: Untrusted triggers + unsafe checkout + cache actions
// 2. Cache hierarchy exploitation: Workflows that can write to default branch cache
// 3. Cache eviction risk: Multiple cache actions that could enable cache flooding
type CachePoisoningRule struct {
	BaseRule
	unsafeTriggers      []string
	checkoutUnsafeRef   bool
	unsafeCheckoutStep  *ast.Step
	autoFixerRegistered bool
	// New fields for extended detection
	hasPushToDefaultBranch bool
	hasExternalTrigger     bool // workflow_dispatch, schedule, repository_dispatch
	cacheActionCount       int
	workflowTriggers       []string
}

// NewCachePoisoningRule creates a new cache poisoning detection rule.
func NewCachePoisoningRule() *CachePoisoningRule {
	return &CachePoisoningRule{
		BaseRule: BaseRule{
			RuleName: "cache-poisoning",
			RuleDesc: "Detects potential cache poisoning vulnerabilities when using cache with untrusted triggers",
		},
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
	rule.hasPushToDefaultBranch = false
	rule.hasExternalTrigger = false
	rule.cacheActionCount = 0
	rule.workflowTriggers = nil

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil {
				triggerName := e.Hook.Value
				rule.workflowTriggers = append(rule.workflowTriggers, triggerName)

				if IsUnsafeTrigger(triggerName) {
					rule.unsafeTriggers = append(rule.unsafeTriggers, triggerName)
				}

				// Check for push to default branch (cache hierarchy exploitation risk)
				if triggerName == "push" {
					rule.hasPushToDefaultBranch = rule.isPushToDefaultBranch(e)
				}

				// Check for external triggers (can be exploited for cache hierarchy attacks)
				if triggerName == SubWorkflowDispatch || triggerName == SubSchedule ||
					triggerName == SubRepositoryDispatch {
					rule.hasExternalTrigger = true
				}
			}
		case *ast.ScheduledEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubSchedule)
			rule.hasExternalTrigger = true
		case *ast.WorkflowDispatchEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubWorkflowDispatch)
			rule.hasExternalTrigger = true
		case *ast.RepositoryDispatchEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubRepositoryDispatch)
			rule.hasExternalTrigger = true
		}
	}

	return nil
}

// isPushToDefaultBranch checks if push event targets default branch (main/master)
func (rule *CachePoisoningRule) isPushToDefaultBranch(event *ast.WebhookEvent) bool {
	// If no branch filter, it includes default branch
	if event.Branches == nil {
		return true
	}

	// Check if any branch filter includes default branch
	for _, branch := range event.Branches.Values {
		if branch != nil {
			branchName := branch.Value
			if branchName == "main" || branchName == "master" ||
				branchName == "**" || branchName == "*" {
				return true
			}
		}
	}

	return false
}

func (rule *CachePoisoningRule) VisitWorkflowPost(node *ast.Workflow) error {
	// Check for cache eviction risk: multiple cache actions can enable cache flooding attacks
	// GitHub has a 10GB cache limit per repository - attackers can fill it to evict legitimate caches
	if rule.cacheActionCount >= 5 {
		// Use workflow name position if available, otherwise use line 1
		var pos *ast.Position
		if node.Name != nil && node.Name.Pos != nil {
			pos = node.Name.Pos
		} else {
			pos = &ast.Position{Line: 1, Col: 1}
		}
		rule.Errorf(
			pos,
			"cache eviction risk: workflow uses %d cache actions. "+
				"Multiple caches increase risk of cache flooding attacks where attackers fill the 10GB repository limit "+
				"to evict legitimate caches. Consider consolidating caches or using cache-read-only for non-critical jobs",
			rule.cacheActionCount,
		)
	}
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

	// Check for cache actions
	if isCacheAction(uses, action.Inputs) {
		rule.cacheActionCount++

		// Check cache hierarchy exploitation risk
		rule.checkCacheHierarchyExploitation(node, uses)

		// Check for indirect cache poisoning (unsafe checkout + cache action)
		if len(rule.unsafeTriggers) > 0 && rule.checkoutUnsafeRef {
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
	}

	return nil
}

// checkCacheHierarchyExploitation detects cache hierarchy exploitation vulnerabilities
// GitHub Actions caches are scoped by branch - PRs can read caches from their base branch.
// If an attacker can write to the default branch's cache, they can poison all downstream PRs.
func (rule *CachePoisoningRule) checkCacheHierarchyExploitation(node *ast.Step, _ string) {
	// Risk: External triggers (workflow_dispatch, schedule) combined with push to default branch
	// Attackers can trigger workflow_dispatch to write poisoned cache, which PRs will read
	if rule.hasExternalTrigger && rule.hasPushToDefaultBranch {
		rule.Errorf(
			node.Pos,
			"cache hierarchy exploitation risk: workflow with external triggers (%s) and push to default branch "+
				"can be exploited to poison caches. Attacker can trigger workflow_dispatch/schedule to write "+
				"malicious cache that all PRs will read. Consider using PR-scoped cache keys or separate workflows",
			strings.Join(rule.workflowTriggers, ", "),
		)
		return
	}

	// Risk: External triggers alone can write to default branch cache
	if rule.hasExternalTrigger && !rule.hasPushToDefaultBranch {
		// Only warn if there's no branch restriction (workflow runs on default branch by default)
		hasPushTrigger := false
		for _, trigger := range rule.workflowTriggers {
			if trigger == "push" {
				hasPushTrigger = true
				break
			}
		}
		if !hasPushTrigger {
			rule.Errorf(
				node.Pos,
				"cache hierarchy exploitation risk: workflow with external trigger (%s) writes to default branch cache. "+
					"Attackers can exploit this to poison caches read by all PRs. "+
					"Consider using immutable cache keys with github.sha",
				strings.Join(rule.workflowTriggers, ", "),
			)
		}
	}
}

func (rule *CachePoisoningRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}
	return RemoveRefFromWith(node.BaseNode)
}
