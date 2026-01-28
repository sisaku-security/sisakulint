package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// ArtifactPoisoningMedium detects potential artifact poisoning vulnerabilities
// when third-party artifact download actions are used in workflows triggered by untrusted events.
//
// This rule differs from artifact-poisoning-critical:
//   - critical: Detects actions/download-artifact with unsafe extraction paths
//   - medium: Detects third-party artifact download actions (like dawidd6/action-download-artifact)
//     used with untrusted triggers, which may download and extract artifacts unsafely by default
//
// Detection conditions:
// 1. Workflow is triggered by untrusted events (workflow_run, pull_request_target, issue_comment)
// 2. Third-party artifact download action is used (excluding actions/download-artifact)
//
// Based on CodeQL query: https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-medium/
type ArtifactPoisoningMedium struct {
	BaseRule
	unsafeTriggers []string
}

// NewArtifactPoisoningMediumRule creates a new artifact poisoning medium severity detection rule.
func NewArtifactPoisoningMediumRule() *ArtifactPoisoningMedium {
	return &ArtifactPoisoningMedium{
		BaseRule: BaseRule{
			RuleName: "artifact-poisoning-medium",
			RuleDesc: "Detects third-party artifact download actions in workflows with untrusted triggers. These actions may download and extract artifacts unsafely, allowing file overwrites.",
		},
	}
}

// knownThirdPartyArtifactActions lists known third-party actions that download artifacts.
// These actions may have unsafe default behavior (e.g., overwriting existing files).
var knownThirdPartyArtifactActions = map[string]bool{
	"dawidd6/action-download-artifact": true, // Downloads artifacts from other workflows
	// Add more third-party artifact download actions as they are discovered
}

// isThirdPartyArtifactAction checks if the action is a third-party artifact download action.
// It excludes actions/download-artifact which is handled by the critical rule.
func isThirdPartyArtifactAction(uses string) bool {
	if uses == "" {
		return false
	}

	// Extract action name without version
	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	// Exclude official actions/download-artifact (handled by critical rule)
	if strings.HasPrefix(actionName, "actions/download-artifact") {
		return false
	}

	// Check against known third-party artifact download actions
	if knownThirdPartyArtifactActions[actionName] {
		return true
	}

	// Heuristic: Check if action name suggests artifact downloading
	// This catches variations and new actions with similar naming patterns
	lowerName := strings.ToLower(actionName)
	if strings.Contains(lowerName, "download") && strings.Contains(lowerName, "artifact") {
		return true
	}

	return false
}

func (rule *ArtifactPoisoningMedium) VisitWorkflowPre(node *ast.Workflow) error {
	// Reset state for new workflow
	rule.unsafeTriggers = nil

	// Detect untrusted triggers
	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil && UntrustedTriggers[e.Hook.Value] {
				rule.unsafeTriggers = append(rule.unsafeTriggers, e.Hook.Value)
			}
		}
	}

	return nil
}

func (rule *ArtifactPoisoningMedium) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

func (rule *ArtifactPoisoningMedium) VisitJobPre(node *ast.Job) error {
	return nil
}

func (rule *ArtifactPoisoningMedium) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *ArtifactPoisoningMedium) VisitStep(node *ast.Step) error {
	// Only check if workflow has untrusted triggers
	if len(rule.unsafeTriggers) == 0 {
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	// Check if this is a third-party artifact download action
	if !isThirdPartyArtifactAction(uses) {
		return nil
	}

	// Check if the action already has a safe path configured
	hasSafePath := false
	if pathInput, ok := action.Inputs["path"]; ok && pathInput != nil && pathInput.Value != nil {
		pathValue := pathInput.Value.Value
		// Check if path uses runner.temp (safe extraction location)
		if strings.Contains(pathValue, "runner.temp") || strings.Contains(pathValue, "RUNNER_TEMP") {
			hasSafePath = true
		}
	}

	// Report the issue
	triggers := strings.Join(rule.unsafeTriggers, ", ")

	if hasSafePath {
		// Path is configured safely, but still warn about untrusted content
		rule.Errorf(
			node.Pos,
			"artifact poisoning risk: third-party action %q downloads artifacts in workflow with untrusted triggers (%s). Even with safe extraction paths, validate artifact content before use (checksums, signatures) and avoid executing scripts directly. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningmedium/",
			uses,
			triggers,
		)
		// No auto-fixer needed when path is already safe
	} else {
		// Path not configured or unsafe
		rule.Errorf(
			node.Pos,
			"artifact poisoning risk: third-party action %q downloads artifacts in workflow with untrusted triggers (%s) without safe extraction path. This may allow malicious artifacts to overwrite existing files. Extract to '${{ runner.temp }}/artifacts' and validate content before use. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningmedium/",
			uses,
			triggers,
		)
		// Add auto-fixer to add safe path
		rule.AddAutoFixer(NewStepFixer(node, rule))
	}

	return nil
}

// FixStep adds a safe extraction path to the third-party artifact download action
func (rule *ArtifactPoisoningMedium) FixStep(node *ast.Step) error {
	action := node.Exec.(*ast.ExecAction)

	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	// Add or update path input to use runner.temp
	action.Inputs["path"] = &ast.Input{
		Name: &ast.String{
			Value: "path",
			Pos:   node.Pos,
		},
		Value: &ast.String{
			Value: "${{ runner.temp }}/artifacts",
			Pos:   node.Pos,
		},
	}

	// Update the YAML node to reflect the change (must be called for file to be modified)
	AddPathToWithSection(node.BaseNode, "${{ runner.temp }}/artifacts")
	return nil
}
