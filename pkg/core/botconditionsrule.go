package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// BotConditionsRule detects spoofable bot detection conditions in GitHub Actions workflows.
// This rule identifies scenarios where bot checks use spoofable contexts like github.actor
// instead of event-specific safe contexts.
//
// Vulnerable pattern:
//
//	on: pull_request_target
//	jobs:
//	  auto-merge:
//	    if: github.actor == 'dependabot[bot]'
//	    steps:
//	      - run: gh pr merge --auto  # Attacker's PR could be auto-merged
//
// Safe pattern:
//
//	on: pull_request_target
//	jobs:
//	  auto-merge:
//	    if: github.event.pull_request.user.login == 'dependabot[bot]'
//	    steps:
//	      - run: gh pr merge --auto
//
// References:
// - https://github.com/woodruffw/zizmor/blob/main/crates/zizmor/src/audit/bot_conditions.rs
type BotConditionsRule struct {
	BaseRule
	// currentWorkflow stores the current workflow being analyzed
	currentWorkflow *ast.Workflow
	// currentTriggerEvent stores the primary trigger event for replacement suggestions
	currentTriggerEvent string
}

// spoofableActorContexts lists contexts that can be spoofed by attackers
var spoofableActorContexts = []string{
	"github.actor",
	"github.triggering_actor",
	"github.event.pull_request.sender.login",
}

// spoofableActorIDContexts lists ID contexts that can also be spoofed
var spoofableActorIDContexts = []string{
	"github.actor_id",
	"github.event.pull_request.sender.id",
}

// knownBotActorIDs lists known bot actor IDs
var knownBotActorIDs = []string{
	"29110",    // dependabot integration ID
	"49699333", // dependabot[bot]
	"27856297", // dependabot-preview[bot]
	"29139614", // renovate[bot]
}

// safeContextReplacements maps trigger events to safe context replacements
var safeContextReplacements = map[string]struct {
	login string
	id    string
}{
	"pull_request_target": {
		login: "github.event.pull_request.user.login",
		id:    "github.event.pull_request.user.id",
	},
	"pull_request": {
		login: "github.event.pull_request.user.login",
		id:    "github.event.pull_request.user.id",
	},
	"issue_comment": {
		login: "github.event.comment.user.login",
		id:    "github.event.comment.user.id",
	},
	"pull_request_review": {
		login: "github.event.review.user.login",
		id:    "github.event.review.user.id",
	},
	"pull_request_review_comment": {
		login: "github.event.comment.user.login",
		id:    "github.event.comment.user.id",
	},
	"issues": {
		login: "github.event.issue.user.login",
		id:    "github.event.issue.user.id",
	},
	"release": {
		login: "github.event.release.author.login",
		id:    "github.event.release.author.id",
	},
	"workflow_run": {
		login: "github.event.workflow_run.actor.login",
		id:    "github.event.workflow_run.actor.id",
	},
}

// defaultSafeContext is used when the trigger event doesn't have a specific mapping
var defaultSafeContext = struct {
	login string
	id    string
}{
	login: "github.event.sender.login",
	id:    "github.event.sender.id",
}

// botSuffixPattern matches bot account names like 'dependabot[bot]'
var botSuffixPattern = regexp.MustCompile(`['"][\w-]+\[bot\]['"]`)

// NewBotConditionsRule creates a new instance of the bot conditions rule
func NewBotConditionsRule() *BotConditionsRule {
	return &BotConditionsRule{
		BaseRule: BaseRule{
			RuleName: "bot-conditions",
			RuleDesc: "Detects spoofable bot detection conditions using github.actor or similar contexts",
		},
	}
}

// VisitWorkflowPre analyzes the workflow triggers to determine safe replacements
func (rule *BotConditionsRule) VisitWorkflowPre(n *ast.Workflow) error {
	rule.currentWorkflow = n
	rule.currentTriggerEvent = ""

	// Find the first webhook event that has a safe replacement mapping
	for _, event := range n.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}

		eventName := webhookEvent.EventName()
		if _, exists := safeContextReplacements[eventName]; exists {
			rule.currentTriggerEvent = eventName
			break
		}
	}

	return nil
}

// VisitJobPre checks job-level if conditions for spoofable bot checks
func (rule *BotConditionsRule) VisitJobPre(n *ast.Job) error {
	if n.If != nil && n.If.Value != "" {
		rule.checkCondition(n.If, "job", n.Pos)
	}
	return nil
}

// VisitStep checks step-level if conditions for spoofable bot checks
func (rule *BotConditionsRule) VisitStep(n *ast.Step) error {
	if n.If != nil && n.If.Value != "" {
		rule.checkCondition(n.If, "step", n.Pos)
	}
	return nil
}

// checkCondition analyzes a condition for spoofable bot detection patterns
func (rule *BotConditionsRule) checkCondition(condition *ast.String, level string, pos *ast.Position) {
	if condition == nil || condition.Value == "" {
		return
	}

	conditionValue := condition.Value

	// Check for spoofable actor name contexts with bot pattern
	for _, ctx := range spoofableActorContexts {
		if rule.isBotCondition(conditionValue, ctx) {
			isDominant := rule.isDominantCondition(conditionValue, ctx)
			rule.reportSpoofableCondition(condition, ctx, isDominant, false, pos)
			return
		}
	}

	// Check for spoofable actor ID contexts with known bot IDs
	for _, ctx := range spoofableActorIDContexts {
		if rule.isBotIDCondition(conditionValue, ctx) {
			isDominant := rule.isDominantCondition(conditionValue, ctx)
			rule.reportSpoofableCondition(condition, ctx, isDominant, true, pos)
			return
		}
	}
}

// isBotCondition checks if the condition contains a bot check using the given context
func (rule *BotConditionsRule) isBotCondition(condition string, context string) bool {
	if !strings.Contains(condition, context) {
		return false
	}

	// Check if comparing with a [bot] pattern
	return botSuffixPattern.MatchString(condition)
}

// isBotIDCondition checks if the condition contains a bot ID check using the given context
func (rule *BotConditionsRule) isBotIDCondition(condition string, context string) bool {
	if !strings.Contains(condition, context) {
		return false
	}

	// Check if comparing with known bot IDs
	for _, botID := range knownBotActorIDs {
		// Match patterns like: github.actor_id == '49699333' or github.actor_id == 49699333
		if strings.Contains(condition, botID) {
			return true
		}
	}

	return false
}

// isDominantCondition determines if the spoofable condition is "dominant"
// A dominant condition is one that, if true, causes the job/step to execute
// regardless of other conditions (i.e., connected by OR operators)
func (rule *BotConditionsRule) isDominantCondition(condition string, context string) bool {
	// Simple heuristic: if the condition contains the context and is connected by ||,
	// it's likely dominant. If connected only by &&, it's not dominant.

	// Find the part containing the context
	idx := strings.Index(condition, context)
	if idx == -1 {
		return false
	}

	// Check if the condition is a simple equality check (no AND)
	// or if it's part of an OR chain
	lowerCondition := strings.ToLower(condition)

	// If there's no AND operator at all, it's dominant
	if !strings.Contains(lowerCondition, "&&") {
		return true
	}

	// If there's an OR operator, check if the bot condition is part of an OR chain
	if strings.Contains(lowerCondition, "||") {
		// Check if the OR is at a higher precedence level than AND around our context
		// This is a simplified check - we look at what's immediately around the context
		beforeCtx := condition[:idx]
		afterCtxEnd := idx + len(context)
		afterCtx := ""
		if afterCtxEnd < len(condition) {
			afterCtx = condition[afterCtxEnd:]
		}

		// Find the nearest logical operators before and after
		lastOrBefore := strings.LastIndex(beforeCtx, "||")
		lastAndBefore := strings.LastIndex(beforeCtx, "&&")
		firstOrAfter := strings.Index(afterCtx, "||")
		firstAndAfter := strings.Index(afterCtx, "&&")

		// If OR is closer than AND (or no AND nearby), it's more likely dominant
		if lastOrBefore > lastAndBefore {
			return true
		}
		if firstOrAfter != -1 && (firstAndAfter == -1 || firstOrAfter < firstAndAfter) {
			return true
		}
	}

	return false
}

// reportSpoofableCondition reports the spoofable bot condition issue
func (rule *BotConditionsRule) reportSpoofableCondition(condition *ast.String, context string, isDominant bool, isIDContext bool, pos *ast.Position) {
	confidence := "Medium"
	if isDominant {
		confidence = "High"
	}

	safeCtx := rule.getSafeReplacement(isIDContext)

	rule.Errorf(
		condition.Pos,
		"spoofable bot condition detected (%s confidence): using '%s' for bot detection is vulnerable to spoofing. "+
			"Attackers can create accounts with similar names to bypass this check. "+
			"Use '%s' instead which is tied to the specific event. "+
			"See https://github.com/woodruffw/zizmor/blob/main/docs/audits.md#bot-conditions",
		confidence,
		context,
		safeCtx,
	)

	// Add auto-fixer
	rule.AddAutoFixer(newBotConditionsFixer(rule.RuleName, condition, context, safeCtx, isIDContext))
}

// getSafeReplacement returns the safe replacement context based on the trigger event
func (rule *BotConditionsRule) getSafeReplacement(isIDContext bool) string {
	if rule.currentTriggerEvent != "" {
		if replacement, exists := safeContextReplacements[rule.currentTriggerEvent]; exists {
			if isIDContext {
				return replacement.id
			}
			return replacement.login
		}
	}

	if isIDContext {
		return defaultSafeContext.id
	}
	return defaultSafeContext.login
}

// VisitJobPost is required by the TreeVisitor interface
func (rule *BotConditionsRule) VisitJobPost(n *ast.Job) error {
	return nil
}

// VisitWorkflowPost resets state after workflow processing
func (rule *BotConditionsRule) VisitWorkflowPost(n *ast.Workflow) error {
	rule.currentWorkflow = nil
	rule.currentTriggerEvent = ""
	return nil
}

// botConditionsFixer is a custom fixer for bot conditions
type botConditionsFixer struct {
	BaseAutoFixer
	condition   *ast.String
	oldContext  string
	newContext  string
	isIDContext bool
}

// newBotConditionsFixer creates a new fixer for bot conditions
func newBotConditionsFixer(ruleName string, condition *ast.String, oldContext, newContext string, isIDContext bool) AutoFixer {
	return &botConditionsFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: ruleName},
		condition:     condition,
		oldContext:    oldContext,
		newContext:    newContext,
		isIDContext:   isIDContext,
	}
}

// Fix implements the AutoFixer interface
func (f *botConditionsFixer) Fix() error {
	if f.condition == nil {
		return nil
	}

	oldValue := f.condition.Value
	newValue := strings.ReplaceAll(oldValue, f.oldContext, f.newContext)

	// Update both BaseNode and Value for proper YAML output
	if f.condition.BaseNode != nil {
		f.condition.BaseNode.Value = newValue
	}
	f.condition.Value = newValue

	return nil
}
