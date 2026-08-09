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
	// workflowTriggers stores all trigger names from the workflow, collected in VisitWorkflowPre.
	workflowTriggers []string
	// jobHasPrivilegedTrigger indicates whether the current job can execute on a trigger
	// that lets a less-trusted actor influence this run (see JobTriggerAnalyzer.HasPrivilegedTrigger).
	// Without one, actions/download-artifact can only ever fetch artifacts uploaded earlier
	// in this SAME run by equally-trusted sibling jobs, so there is no untrusted producer to poison.
	jobHasPrivilegedTrigger bool
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

	// LabelsExpr is set for both plain strings (e.g. "ubuntu-latest") and real
	// expressions (e.g. "${{ matrix.os }}") because the parser stores all scalar
	// runs-on values there. Only treat it as opaque when it actually contains
	// an expression, following the same pattern as selfhostedrunnersrule.go.
	if runner.LabelsExpr != nil {
		if strings.Contains(runner.LabelsExpr.Value, "${{") {
			return "unknown"
		}
		// Plain string label — fall through to match against it directly.
		v := runner.LabelsExpr.Value
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
// directory with no path-traversal segments.
//
// Only the `${{ runner.temp }}` expression form counts. A literal `$RUNNER_TEMP`
// is NOT equivalent: `with:` inputs are not shell-expanded, so the action receives
// the string as-is and resolves it relative to its working directory, producing a
// directory literally named `$RUNNER_TEMP` inside GITHUB_WORKSPACE. Treating it as
// safe inverted the verdict for the one case it was meant to allow.
func isRunnerTempPath(path string) bool {
	for _, prefix := range []string{"${{ runner.temp }}"} {
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

	// Windows absolute paths: no literal Windows path is on the safe list, so every
	// drive-rooted path is reported. Only the `${{ runner.temp }}` expression form is
	// treated as safe, and that is handled above before this OS dispatch.
	//
	// Note this check cannot prove a path is outside the workspace: the workspace root
	// is not knowable from the workflow file on any OS. The Unix allow-list below
	// (/tmp and /var) assumes the GitHub-hosted layout rather than proving anything.
	if isWindowsAbsPath(path) {
		return true
	}

	// Everything else (relative paths, bare names, etc.)
	return true
}

// VisitWorkflowPre collects the workflow's triggers so VisitJobPre can determine
// whether a job's download-artifact steps could plausibly consume an artifact
// produced by a less-trusted actor.
func (rule *ArtifactPoisoning) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflowTriggers = nil
	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil {
				rule.workflowTriggers = append(rule.workflowTriggers, e.Hook.Value)
			}
		case *ast.WorkflowCallEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, "workflow_call")
		}
	}
	return nil
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

	// Use JobTriggerAnalyzer (not workflow.On directly) so job-level if: conditions
	// that filter out a privileged trigger are respected, same as codeinjection.go.
	analyzer := NewJobTriggerAnalyzer(rule.workflowTriggers)
	rule.jobHasPrivilegedTrigger = analyzer.HasPrivilegedTrigger(job)

	return nil
}

// VisitJobPost is a no-op but required by the Rule interface.
func (rule *ArtifactPoisoning) VisitJobPost(job *ast.Job) error {
	return nil
}

// hasCrossRunArtifactInputs reports whether a download-artifact step is actually
// configured to fetch an artifact from a different run/repository.
//
// In actions/download-artifact the cross-run/cross-repo fetch (options.findBy) is
// populated ONLY inside the `if (inputs.token)` branch: without a github-token the
// run-id and repository inputs are ignored and the action reads the CURRENT run.
// This gate is invariant across download-artifact v4.0.0..v8.0.1. So a genuine
// foreign target requires BOTH a github-token AND a run-id/repository that resolves
// somewhere other than this run/repo. A token-less run-id/repository (the action
// silently ignores it), or one pinned back to the current context via
// github.run_id/github.repository, still resolves to this same run and is not a
// cross-run poisoning vector.
func hasCrossRunArtifactInputs(action *ast.ExecAction) bool {
	// No github-token => the action cannot reach another run; run-id/repository are ignored.
	if !hasNonEmptyInput(action, "github-token") {
		return false
	}
	for _, name := range []string{"run-id", "repository"} {
		input, ok := action.Inputs[name]
		if !ok || input == nil || input.Value == nil {
			continue
		}
		value := strings.TrimSpace(input.Value.Value)
		if value == "" {
			continue
		}
		// A self-reference (run-id: ${{ github.run_id }} / repository: ${{ github.repository }})
		// pins the download back to the current run/repo => not a foreign target.
		if name == "run-id" && isCurrentContextExpr(value, "github.run_id") {
			continue
		}
		if name == "repository" && isCurrentContextExpr(value, "github.repository") {
			continue
		}
		return true
	}
	return false
}

// hasNonEmptyInput reports whether the action sets input `name` to a non-blank value.
func hasNonEmptyInput(action *ast.ExecAction, name string) bool {
	input, ok := action.Inputs[name]
	return ok && input != nil && input.Value != nil && strings.TrimSpace(input.Value.Value) != ""
}

// isCurrentContextExpr reports whether value is exactly the single GitHub expression
// ctx (e.g. "${{ github.run_id }}"), i.e. a redundant self-reference to the current
// run/repo rather than a foreign one.
func isCurrentContextExpr(value, ctx string) bool {
	s := strings.TrimSpace(value)
	if !strings.HasPrefix(s, "${{") || !strings.HasSuffix(s, "}}") {
		return false
	}
	return strings.TrimSpace(s[3:len(s)-2]) == ctx
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

	// Skip if this download can only ever pull artifacts uploaded earlier in this SAME
	// run. actions/download-artifact defaults to the current run; it only reaches into a
	// different (potentially less-trusted) run when the workflow itself is invoked from one
	// (workflow_run, pull_request_target, etc. - see JobTriggerAnalyzer.HasPrivilegedTrigger)
	// or the step is actually configured to reach a foreign run (github-token + a
	// non-self 'run-id'/'repository'; see hasCrossRunArtifactInputs). Without either,
	// every artifact in this run was uploaded by an equally-trusted sibling job, so there is
	// no untrusted producer for "artifact poisoning" to poison. This is the same fan-out/fan-in
	// pattern GitHub's own docs recommend for splitting a build across OS runners.
	if !rule.jobHasPrivilegedTrigger && !hasCrossRunArtifactInputs(action) {
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
