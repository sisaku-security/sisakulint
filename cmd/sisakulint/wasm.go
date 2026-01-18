//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/sisaku-security/sisakulint/pkg/core"
)

// LintError represents a single linting error for JSON serialization.
type LintError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
	Rule    string `json:"rule"`
}

// LintResult represents the result of linting for JSON serialization.
type LintResult struct {
	Filename string      `json:"filename"`
	Errors   []LintError `json:"errors"`
	Success  bool        `json:"success"`
}

// makeWASMRules creates rules that are compatible with WASM environment.
// Rules that require HTTP requests or use sync.Once are excluded.
func makeWASMRules() []core.Rule {
	return []core.Rule{
		core.CredentialsRule(),
		core.JobNeedsRule(),
		core.EnvironmentVariableRule(),
		core.IDRule(),
		core.PermissionsRule(),
		core.DeprecatedCommandsRule(),
		core.NewConditionalRule(),
		core.TimeoutMinuteRule(),
		core.CodeInjectionCriticalRule(),
		core.CodeInjectionMediumRule(),
		core.EnvVarInjectionCriticalRule(),
		core.EnvVarInjectionMediumRule(),
		core.EnvPathInjectionCriticalRule(),
		core.EnvPathInjectionMediumRule(),
		core.NewUntrustedCheckoutRule(),
		core.NewCachePoisoningRule(),
		core.NewCachePoisoningPoisonableStepRule(),
		core.NewSecretExposureRule(),
		core.NewUnmaskedSecretExposureRule(),
		core.NewImproperAccessControlRule(),
		core.NewUntrustedCheckoutTOCTOUCriticalRule(),
		core.NewUntrustedCheckoutTOCTOUHighRule(),
		core.NewBotConditionsRule(),
		core.NewArtipackedRule(),
		core.NewUnsoundContainsRule(),
		core.NewSelfHostedRunnersRule(),
		core.ArtifactPoisoningRule(),
		core.NewArtifactPoisoningMediumRule(),
	}
}

func analyzeYAML(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return `{"success":false,"errors":[{"line":0,"column":0,"message":"analyzeYAML requires 2 arguments: yamlContent and filename","rule":"wasm-api"}]}`
	}

	yamlContent := args[0].String()
	filename := args[1].String()

	// Parse the workflow YAML directly
	parsedWorkflow, parseErrors := core.Parse([]byte(yamlContent))

	// Collect all errors
	var allErrors []*core.LintingError
	allErrors = append(allErrors, parseErrors...)

	// Apply WASM-compatible rules if parsing succeeded
	if parsedWorkflow != nil {
		rules := makeWASMRules()

		v := core.NewSyntaxTreeVisitor()
		for _, rule := range rules {
			v.AddVisitor(rule)
		}

		if err := v.VisitTree(parsedWorkflow); err != nil {
			errResult := LintResult{
				Filename: filename,
				Success:  false,
				Errors: []LintError{
					{Line: 0, Column: 0, Message: "Validation failed: " + err.Error(), Rule: "wasm-api"},
				},
			}
			jsonBytes, _ := json.Marshal(errResult)
			return string(jsonBytes)
		}

		for _, rule := range rules {
			allErrors = append(allErrors, rule.Errors()...)
		}
	}

	lintResult := LintResult{
		Filename: filename,
		Errors:   make([]LintError, 0, len(allErrors)),
		Success:  len(allErrors) == 0,
	}

	for _, e := range allErrors {
		lintResult.Errors = append(lintResult.Errors, LintError{
			Line:    e.LineNumber,
			Column:  e.ColNumber,
			Message: e.Description,
			Rule:    e.Type,
		})
	}

	jsonBytes, err := json.Marshal(lintResult)
	if err != nil {
		return `{"success":false,"errors":[{"line":0,"column":0,"message":"Failed to marshal result","rule":"wasm-api"}]}`
	}

	return string(jsonBytes)
}

func init() {
	js.Global().Set("sisakulintAnalyze", js.FuncOf(analyzeYAML))
}

func main() {
	// Block forever to keep the Go runtime alive for JavaScript callbacks
	<-make(chan struct{})
}
