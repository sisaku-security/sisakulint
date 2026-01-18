package core

import (
	"path"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

const shellCmd = "cmd"

// ObfuscationRule detects obfuscated workflow patterns that may evade security scanners.
type ObfuscationRule struct {
	BaseRule
}

func NewObfuscationRule() *ObfuscationRule {
	return &ObfuscationRule{
		BaseRule: CreateBaseRule(
			"obfuscation",
			"Detects obfuscated workflow patterns that may be used to evade security scanners",
		),
	}
}

func checkUsesPathObfuscation(usesValue string) []string {
	atIndex := strings.LastIndex(usesValue, "@")
	if atIndex == -1 {
		return nil
	}

	pathPart := usesValue[:atIndex]
	components := strings.Split(pathPart, "/")
	if len(components) < 2 {
		return nil
	}

	var annotations []string
	for i, component := range components {
		if i < 2 {
			continue
		}

		switch component {
		case ".":
			annotations = append(annotations, "contains '.' (current directory reference)")
		case "..":
			annotations = append(annotations, "contains '..' (parent directory traversal)")
		case "":
			annotations = append(annotations, "contains empty path component (consecutive slashes)")
		}
	}

	return annotations
}

func normalizeUsesPath(usesValue string) string {
	atIndex := strings.LastIndex(usesValue, "@")
	if atIndex == -1 {
		return ""
	}

	pathPart := usesValue[:atIndex]
	ref := usesValue[atIndex+1:]

	parts := strings.SplitN(pathPart, "/", 3)
	if len(parts) < 2 {
		return ""
	}

	owner := parts[0]
	repo := parts[1]

	if len(parts) < 3 || parts[2] == "" {
		// Handle edge case: empty owner/repo from malformed input like "/@v4"
		if owner == "" || repo == "" {
			return ""
		}
		return owner + "/" + repo + "@" + ref
	}

	subpath := parts[2]
	// Use path.Clean (not filepath.Clean) for consistent behavior across platforms.
	// This normalizes ".", "..", and consecutive slashes in the subpath.
	cleanedSubpath := path.Clean(subpath)

	if cleanedSubpath == "." || cleanedSubpath == "/" {
		return owner + "/" + repo + "@" + ref
	}

	cleanedSubpath = strings.TrimPrefix(cleanedSubpath, "/")
	if cleanedSubpath == "" {
		return owner + "/" + repo + "@" + ref
	}

	if strings.HasPrefix(cleanedSubpath, "..") {
		return ""
	}

	return owner + "/" + repo + "/" + cleanedSubpath + "@" + ref
}

func isPathObfuscated(usesValue string) bool {
	return len(checkUsesPathObfuscation(usesValue)) > 0
}

func (rule *ObfuscationRule) VisitStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		if action.Uses != nil {
			usesValue := action.Uses.Value
			annotations := checkUsesPathObfuscation(usesValue)
			if len(annotations) > 0 {
				rule.Errorf(action.Uses.Pos,
					"obfuscated 'uses' path in step '%s': %s. Consider normalizing the path.",
					step.String(),
					strings.Join(annotations, ", "))
				rule.AddAutoFixer(NewStepFixer(step, rule))
			}
		}
	}

	if execRun, ok := step.Exec.(*ast.ExecRun); ok {
		if execRun.Shell != nil {
			shellValue := strings.ToLower(execRun.Shell.Value)
			if shellValue == shellCmd {
				rule.Errorf(execRun.Shell.Pos,
					"'shell: cmd' in step '%s'. CMD shell is difficult to analyze and may obfuscate malicious commands. Consider using PowerShell or bash.",
					step.String())
			}
		}
	}

	return nil
}

func (rule *ObfuscationRule) VisitJobPre(job *ast.Job) error {
	if job.Defaults != nil && job.Defaults.Run != nil && job.Defaults.Run.Shell != nil {
		shellValue := strings.ToLower(job.Defaults.Run.Shell.Value)
		if shellValue == shellCmd {
			rule.Errorf(job.Defaults.Run.Shell.Pos,
				"'shell: cmd' in job '%s' defaults. CMD shell is difficult to analyze and may obfuscate malicious commands. Consider using PowerShell or bash.",
				job.ID.Value)
		}
	}

	if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil {
		usesValue := job.WorkflowCall.Uses.Value
		annotations := checkUsesPathObfuscation(usesValue)
		if len(annotations) > 0 {
			rule.Errorf(job.WorkflowCall.Uses.Pos,
				"obfuscated 'uses' path in workflow call '%s': %s. Consider normalizing the path.",
				job.ID.Value,
				strings.Join(annotations, ", "))
			rule.AddAutoFixer(NewJobFixer(job, rule))
		}
	}

	return nil
}

func (rule *ObfuscationRule) VisitWorkflowPre(workflow *ast.Workflow) error {
	if workflow.Defaults != nil && workflow.Defaults.Run != nil && workflow.Defaults.Run.Shell != nil {
		shellValue := strings.ToLower(workflow.Defaults.Run.Shell.Value)
		if shellValue == shellCmd {
			rule.Errorf(workflow.Defaults.Run.Shell.Pos,
				"'shell: cmd' in workflow defaults. CMD shell is difficult to analyze and may obfuscate malicious commands. Consider using PowerShell or bash.")
		}
	}
	return nil
}

func (rule *ObfuscationRule) FixStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		if action.Uses != nil && action.Uses.BaseNode != nil {
			usesValue := action.Uses.Value
			if isPathObfuscated(usesValue) {
				normalized := normalizeUsesPath(usesValue)
				if normalized != "" && normalized != usesValue {
					action.Uses.BaseNode.Value = normalized
					action.Uses.Value = normalized
				}
			}
		}
	}
	return nil
}

func (rule *ObfuscationRule) FixJob(job *ast.Job) error {
	if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil && job.WorkflowCall.Uses.BaseNode != nil {
		usesValue := job.WorkflowCall.Uses.Value
		if isPathObfuscated(usesValue) {
			normalized := normalizeUsesPath(usesValue)
			if normalized != "" && normalized != usesValue {
				job.WorkflowCall.Uses.BaseNode.Value = normalized
				job.WorkflowCall.Uses.Value = normalized
			}
		}
	}
	return nil
}
