package core

import (
	pathpkg "path"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type ArtifactPoisoning struct {
	BaseRule
	hasCheckout   bool // Tracks if the current job checks out the repository
	currentRunsOn *ast.Runner
}

func ArtifactPoisoningRule() *ArtifactPoisoning {
	return &ArtifactPoisoning{
		BaseRule: BaseRule{
			RuleName: "artifact-poisoning-critical",
			RuleDesc: "Detects unsafe artifact downloads that may allow artifact poisoning attacks. Artifacts should be extracted to a temporary folder to prevent overwriting existing files and should be treated as untrusted content.",
		},
	}
}

// detectRunnerOS returns the OS type based on the runner labels.
// Returns "linux", "windows", "macos", or "unknown".
func detectRunnerOS(runner *ast.Runner) string {
	if runner == nil {
		return "unknown"
	}

	// Expression (e.g. ${{ matrix.os }}) - cannot determine OS
	if runner.LabelsExpr != nil {
		return "unknown"
	}

	for _, label := range runner.Labels {
		if label == nil {
			continue
		}
		v := label.Value
		lower := strings.ToLower(v)
		if strings.HasPrefix(lower, "ubuntu-") || strings.EqualFold(v, "ubuntu") || strings.EqualFold(v, "linux") {
			return "linux"
		}
		if strings.HasPrefix(lower, "windows-") || strings.EqualFold(v, "windows") {
			return "windows"
		}
		if strings.HasPrefix(lower, "macos-") || strings.EqualFold(v, "macos") || strings.EqualFold(v, "mac") {
			return "macos"
		}
	}
	return "unknown"
}

// isWindowsAbsPath reports whether path is an absolute Windows path (e.g. C:\, D:/).
func isWindowsAbsPath(path string) bool {
	if len(path) < 3 {
		return false
	}
	drive := path[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) &&
		path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

// isRunnerTempPath reports whether path is rooted at the runner's temporary
// directory (${{ runner.temp }} or $RUNNER_TEMP) with no path-traversal segments.
func isRunnerTempPath(path string) bool {
	for _, prefix := range []string{"${{ runner.temp }}", "$RUNNER_TEMP"} {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		if rest == "" {
			return true
		}
		if rest[0] != '/' && rest[0] != '\\' {
			// e.g. "${{ runner.tempDir }}" — not the same variable
			return false
		}
		for _, part := range strings.FieldsFunc(rest, func(r rune) bool {
			return r == '/' || r == '\\'
		}) {
			if part == ".." {
				return false
			}
		}
		return true
	}
	return false
}

// isSafeUnixPath reports whether an absolute Unix path (must start with "/")
// is safe for artifact extraction on Linux/macOS. Only /tmp and /var are
// allowed to avoid false-negatives for workspace paths like /home/runner/work/.
// The path is cleaned first to reject traversal like /tmp/../home/runner/work.
func isSafeUnixPath(path string) bool {
	path = pathpkg.Clean(path)
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/") ||
		path == "/var" || strings.HasPrefix(path, "/var/")
}

// isUnsafePath reports whether path is unsafe for artifact extraction.
// runnerOS must be "linux", "windows", "macos", or "unknown".
// A safe path is one guaranteed to be outside the workspace on the given OS.
func isUnsafePath(path string, runnerOS string) bool {
	if path == "" {
		return true
	}

	path = strings.TrimSpace(path)

	// Workspace-relative paths are unsafe on all OS
	if path == "." || path == "./" {
		return true
	}
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}
	if strings.Contains(path, "github.workspace") {
		return true
	}
	if strings.Contains(path, "GITHUB_WORKSPACE") {
		return true
	}

	// runner.temp is safe on all OS (cross-platform recommended).
	// Use strict prefix matching to avoid matching runner.tempDir or path traversal.
	if isRunnerTempPath(path) {
		return false
	}

	// Unix absolute paths
	if strings.HasPrefix(path, "/") {
		switch runnerOS {
		case "linux", "macos":
			// Only /tmp and /var are safe; /home/runner/work/... is inside the workspace
			return !isSafeUnixPath(path)
		case "windows":
			return true // Wrong OS
		default: // "unknown" - conservative: only /tmp is safe
			cleaned := pathpkg.Clean(path)
			return !(cleaned == "/tmp" || strings.HasPrefix(cleaned, "/tmp/"))
		}
	}

	// Windows absolute paths: drive-rooted paths can point into the checkout
	// workspace (e.g. C:\actions-runner\_work\...) so we cannot safely allow
	// them without knowing the workspace root. Use ${{ runner.temp }} instead.
	if isWindowsAbsPath(path) {
		return true
	}

	// Everything else (relative paths, bare names, etc.)
	return true
}

// VisitJobPre tracks whether the current job checks out the repository.
// Jobs without checkout have no source code to overwrite, making artifact
// poisoning non-exploitable even with workspace-relative paths.
func (rule *ArtifactPoisoning) VisitJobPre(job *ast.Job) error {
	rule.hasCheckout = false
	rule.currentRunsOn = job.RunsOn
	for _, step := range job.Steps {
		if action, ok := step.Exec.(*ast.ExecAction); ok {
			if action.Uses != nil && strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
				rule.hasCheckout = true
				break
			}
		}
	}
	return nil
}

// VisitJobPost is a no-op but required by the Rule interface.
func (rule *ArtifactPoisoning) VisitJobPost(job *ast.Job) error {
	return nil
}

func (rule *ArtifactPoisoning) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if !strings.HasPrefix(action.Uses.Value, "actions/download-artifact@") {
		return nil
	}

	// Skip if job doesn't checkout repository - no files to overwrite
	// This prevents false positives in publish/deploy jobs that only download
	// artifacts to package and publish them (e.g., PyPI, npm publishing)
	if !rule.hasCheckout {
		return nil
	}

	pathInput, hasPath := action.Inputs["path"]
	var pathValue string
	if hasPath && pathInput != nil && pathInput.Value != nil {
		pathValue = pathInput.Value.Value
	}

	if isUnsafePath(pathValue, detectRunnerOS(rule.currentRunsOn)) {
		if pathValue == "" || strings.TrimSpace(pathValue) == "" {
			// Missing or empty path - safe to auto-fix
			rule.Errorf(
				step.Pos,
				"artifact is downloaded without specifying a safe extraction path at step %q. This may allow artifact poisoning where malicious files overwrite existing files. Consider extracting to a temporary folder like '${{ runner.temp }}/artifacts' to prevent overwriting existing files. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/",
				step.String(),
			)
			rule.AddAutoFixer(NewStepFixer(step, rule))
		} else {
			// Unsafe path exists - report error but don't auto-fix (user might have reasons)
			rule.Errorf(
				step.Pos,
				"artifact is downloaded to an unsafe path %q at step %q. Workspace-relative paths allow malicious artifacts to overwrite source code, scripts, or dependencies, creating a critical supply chain vulnerability. Extract to '${{ runner.temp }}/artifacts' instead. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/",
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
