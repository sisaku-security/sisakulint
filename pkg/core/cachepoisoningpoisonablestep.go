package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// CachePoisoningPoisonableStepRule detects potential cache poisoning vulnerabilities
// when untrusted code is executed after checking out PR head code.
// Unlike cache-poisoning rule which detects cache actions, this rule detects
// code execution steps (PoisonableSteps) that can lead to cache token theft.
//
// Detection conditions (all must be met):
// 1. Untrusted triggers (issue_comment, pull_request_target, workflow_run)
// 2. Checking out PR head ref with actions/checkout
// 3. Executing untrusted code (local scripts, local actions, build commands)
type CachePoisoningPoisonableStepRule struct {
	BaseRule
	// workflowTriggers stores all trigger names from the workflow
	workflowTriggers []string
	// unsafeTriggers stores unsafe triggers from the workflow (for error messages)
	unsafeTriggers []string
	// jobUnsafeTriggers stores the effective unsafe triggers for the current job
	// considering job-level if conditions
	jobUnsafeTriggers   []string
	checkoutUnsafeRef   bool
	unsafeCheckoutStep  *ast.Step
	autoFixerRegistered bool
}

// NewCachePoisoningPoisonableStepRule creates a new cache poisoning via poisonable step detection rule.
func NewCachePoisoningPoisonableStepRule() *CachePoisoningPoisonableStepRule {
	return &CachePoisoningPoisonableStepRule{
		BaseRule: BaseRule{
			RuleName: "cache-poisoning-poisonable-step",
			RuleDesc: "Detects potential cache poisoning via execution of untrusted code after unsafe checkout",
		},
	}
}

var (
	localScriptPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^\s*\./`),
		regexp.MustCompile(`\s+\./`),
		regexp.MustCompile(`(?i)^\s*(bash|sh|zsh)\s+\.`),
		regexp.MustCompile(`(?i)^\s*(python|python3)\s+\.`),
		regexp.MustCompile(`(?i)^\s*(node|npx)\s+\.`),
		regexp.MustCompile(`(?i)^\s*(ruby)\s+\.`),
		regexp.MustCompile(`(?i)^\s*(perl)\s+\.`),
		regexp.MustCompile(`(?i)^\s*(php)\s+\.`),
	}

	buildCommandPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^\s*npm\s+(install|ci|run|test|build)`),
		regexp.MustCompile(`(?i)^\s*yarn(\s|$)`),
		regexp.MustCompile(`(?i)^\s*pnpm\s+(install|run|test|build)`),
		regexp.MustCompile(`(?i)^\s*pip\s+install`),
		regexp.MustCompile(`(?i)^\s*pip3\s+install`),
		regexp.MustCompile(`(?i)^\s*(python|python3)\s+-m\s+pip\s+install`),
		regexp.MustCompile(`(?i)^\s*poetry\s+(install|build)`),
		regexp.MustCompile(`(?i)^\s*pipenv\s+install`),
		regexp.MustCompile(`(?i)^\s*make(\s|$)`),
		regexp.MustCompile(`(?i)^\s*cmake(\s|$)`),
		regexp.MustCompile(`(?i)^\s*\./configure`),
		regexp.MustCompile(`(?i)^\s*go\s+(build|install|run|test)`),
		regexp.MustCompile(`(?i)^\s*cargo\s+(build|run|test)`),
		regexp.MustCompile(`(?i)^\s*mvn(\s|$)`),
		regexp.MustCompile(`(?i)^\s*gradle(\s|$)`),
		regexp.MustCompile(`(?i)^\s*bundle\s+(install|exec)`),
		regexp.MustCompile(`(?i)^\s*composer\s+install`),
	}

	githubScriptImportPattern = regexp.MustCompile(`(?i)(require|import)\s*\(\s*['"](\.\/|\$\{\{\s*github\.workspace)`)
)

func isPoisonableLocalScript(script string) bool {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, pattern := range localScriptPatterns {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func isPoisonableBuildCommand(script string) bool {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, pattern := range buildCommandPatterns {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func isPoisonableLocalAction(uses string) bool {
	if uses == "" {
		return false
	}
	return strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\")
}

func isPoisonableGitHubScript(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName != "actions/github-script" {
		return false
	}

	if scriptInput, ok := inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
		return githubScriptImportPattern.MatchString(scriptInput.Value.Value)
	}

	return false
}

func getStepDescription(node *ast.Step) string {
	if node.Name != nil && node.Name.Value != "" {
		return node.Name.Value
	}

	switch exec := node.Exec.(type) {
	case *ast.ExecRun:
		if exec.Run != nil {
			script := exec.Run.Value
			if idx := strings.Index(script, "\n"); idx != -1 {
				script = script[:idx]
			}
			if len(script) > 50 {
				script = script[:50] + "..."
			}
			return "run: " + script
		}
	case *ast.ExecAction:
		if exec.Uses != nil {
			return exec.Uses.Value
		}
	}

	return "step"
}

func (rule *CachePoisoningPoisonableStepRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflowTriggers = nil
	rule.unsafeTriggers = nil
	rule.jobUnsafeTriggers = nil

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil {
				rule.workflowTriggers = append(rule.workflowTriggers, e.Hook.Value)
				if IsUnsafeTrigger(e.Hook.Value) {
					rule.unsafeTriggers = append(rule.unsafeTriggers, e.Hook.Value)
				}
			}
		}
	}

	return nil
}

func (rule *CachePoisoningPoisonableStepRule) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

func (rule *CachePoisoningPoisonableStepRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutUnsafeRef = false
	rule.unsafeCheckoutStep = nil
	rule.autoFixerRegistered = false
	rule.jobUnsafeTriggers = nil

	// If no unsafe triggers in workflow, skip
	if len(rule.unsafeTriggers) == 0 {
		return nil
	}

	// Use JobTriggerAnalyzer to determine effective triggers for this job
	analyzer := NewJobTriggerAnalyzer(rule.workflowTriggers)
	effectiveTriggers := analyzer.AnalyzeJobTriggers(node)

	// Filter to only unsafe triggers that can actually execute this job
	for _, trigger := range effectiveTriggers {
		if IsUnsafeTrigger(trigger) {
			rule.jobUnsafeTriggers = append(rule.jobUnsafeTriggers, trigger)
		}
	}

	if len(rule.jobUnsafeTriggers) == 0 {
		rule.Debug("Job '%s' filtered out unsafe triggers via if condition", node.ID)
	}

	return nil
}

func (rule *CachePoisoningPoisonableStepRule) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *CachePoisoningPoisonableStepRule) VisitStep(node *ast.Step) error {
	// Skip if this job cannot execute on unsafe triggers
	// This considers job-level if conditions that may filter out unsafe triggers
	if len(rule.jobUnsafeTriggers) == 0 {
		return nil
	}

	if action, ok := node.Exec.(*ast.ExecAction); ok && action.Uses != nil {
		uses := action.Uses.Value

		actionName := uses
		if idx := strings.Index(uses, "@"); idx != -1 {
			actionName = uses[:idx]
		}

		if actionName == "actions/checkout" {
			if refInput, ok := action.Inputs["ref"]; ok && refInput != nil && refInput.Value != nil {
				if IsUnsafeCheckoutRef(refInput.Value.Value) {
					rule.checkoutUnsafeRef = true
					rule.unsafeCheckoutStep = node
				}
			}
			return nil
		}

		if rule.checkoutUnsafeRef {
			isPoisonable := false
			var reason string

			if isPoisonableLocalAction(uses) {
				isPoisonable = true
				reason = "local action"
			} else if isPoisonableGitHubScript(uses, action.Inputs) {
				isPoisonable = true
				reason = "github-script with local import"
			}

			if isPoisonable {
				triggers := strings.Join(rule.jobUnsafeTriggers, ", ")
				rule.Errorf(
					node.Pos,
					"cache poisoning risk via %s: '%s' runs untrusted code after checking out PR head (triggers: %s). Attacker can steal cache tokens",
					reason,
					getStepDescription(node),
					triggers,
				)
				rule.registerAutoFixer()
			}
		}
		return nil
	}

	if run, ok := node.Exec.(*ast.ExecRun); ok && run.Run != nil {
		if !rule.checkoutUnsafeRef {
			return nil
		}

		script := run.Run.Value
		isPoisonable := false
		var reason string

		if isPoisonableLocalScript(script) {
			isPoisonable = true
			reason = "local script execution"
		} else if isPoisonableBuildCommand(script) {
			isPoisonable = true
			reason = "build command"
		}

		if isPoisonable {
			triggers := strings.Join(rule.jobUnsafeTriggers, ", ")
			rule.Errorf(
				node.Pos,
				"cache poisoning risk via %s: '%s' runs untrusted code after checking out PR head (triggers: %s). Attacker can steal cache tokens",
				reason,
				getStepDescription(node),
				triggers,
			)
			rule.registerAutoFixer()
		}
	}

	return nil
}

func (rule *CachePoisoningPoisonableStepRule) registerAutoFixer() {
	if rule.unsafeCheckoutStep != nil && !rule.autoFixerRegistered {
		rule.AddAutoFixer(NewStepFixer(rule.unsafeCheckoutStep, rule))
		rule.autoFixerRegistered = true
	}
}

func (rule *CachePoisoningPoisonableStepRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}
	return RemoveRefFromWith(node.BaseNode)
}
