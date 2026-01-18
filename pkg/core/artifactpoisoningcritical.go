package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type ArtifactPoisoning struct {
	BaseRule
}

func ArtifactPoisoningRule() *ArtifactPoisoning {
	return &ArtifactPoisoning{
		BaseRule: BaseRule{
			RuleName: "artifact-poisoning-critical",
			RuleDesc: "Detects unsafe artifact downloads that may allow artifact poisoning attacks. Artifacts should be extracted to a temporary folder to prevent overwriting existing files and should be treated as untrusted content.",
		},
	}
}

// isUnsafePath checks if the provided path is unsafe for artifact extraction.
// Safe paths must use runner.temp to isolate artifacts from the workspace.
// Absolute paths outside the workspace (like /tmp on Linux) are also safe.
func isUnsafePath(path string) bool {
	if path == "" {
		return true
	}

	// Trim whitespace
	path = strings.TrimSpace(path)

	// Workspace-relative paths are unsafe
	if path == "." || path == "./" {
		return true
	}

	// Relative paths (even if not directly in workspace root) are unsafe
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}

	// Check for github.workspace reference (unsafe)
	if strings.Contains(path, "github.workspace") {
		return true
	}

	// Check for GITHUB_WORKSPACE env var (unsafe)
	if strings.Contains(path, "GITHUB_WORKSPACE") {
		return true
	}

	// runner.temp is safe (cross-platform recommended approach)
	if strings.Contains(path, "runner.temp") || strings.Contains(path, "RUNNER_TEMP") {
		return false
	}

	// System temporary directory /tmp is safe (Linux/macOS)
	// This is outside the workspace and cannot overwrite source files
	// Note: We only allow /tmp, not all absolute paths, to maintain security
	if strings.HasPrefix(path, "/tmp/") || path == "/tmp" {
		return false
	}

	// All other paths are unsafe (including relative paths and arbitrary absolute paths)
	// This includes:
	// - Relative paths: "artifacts", "./build"
	// - Workspace paths: "/home/runner/work/repo/artifacts"
	// - Windows paths: "C:\", "D:\" (too broad to safely validate without OS context)
	// - Other absolute paths: "/var/", "/home/", etc.
	return true
}

func (rule *ArtifactPoisoning) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if !strings.HasPrefix(action.Uses.Value, "actions/download-artifact@") {
		return nil
	}

	pathInput, hasPath := action.Inputs["path"]
	var pathValue string
	if hasPath && pathInput != nil && pathInput.Value != nil {
		pathValue = pathInput.Value.Value
	}

	if isUnsafePath(pathValue) {
		if pathValue == "" {
			// Missing or empty path - safe to auto-fix
			rule.Errorf(
				step.Pos,
				"artifact is downloaded without specifying a safe extraction path at step %q. This may allow artifact poisoning where malicious files overwrite existing files. Consider extracting to a temporary folder like '${{ runner.temp }}/artifacts' to prevent overwriting existing files. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/",
				step.String(),
			)
			rule.AddAutoFixer(NewStepFixer(step, rule))
		} else {
			// Unsafe path exists - report error but don't auto-fix (user might have reasons)
			rule.Errorf(
				step.Pos,
				"artifact is downloaded to an unsafe path %q at step %q. Workspace-relative paths allow malicious artifacts to overwrite source code, scripts, or dependencies, creating a critical supply chain vulnerability. Extract to '${{ runner.temp }}/artifacts' instead. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/",
				pathValue,
				step.String(),
			)
			// No auto-fixer for existing unsafe paths to avoid breaking intentional configurations
		}
	}

	return nil
}

func (rule *ArtifactPoisoning) FixStep(step *ast.Step) error {
	action := step.Exec.(*ast.ExecAction)

	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	action.Inputs["path"] = &ast.Input{
		Name: &ast.String{
			Value: "path",
			Pos:   step.Pos,
		},
		Value: &ast.String{
			Value: "${{ runner.temp }}/artifacts",
			Pos:   step.Pos,
		},
	}

	AddPathToWithSection(step.BaseNode, "${{ runner.temp }}/artifacts")
	return nil
}
