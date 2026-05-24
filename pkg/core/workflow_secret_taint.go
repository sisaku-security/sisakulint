package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// WorkflowSecretTaintMap tracks secret-derived values that cross job boundaries
// via jobs.<job>.outputs and needs.<job>.outputs.<name>.
type WorkflowSecretTaintMap struct {
	// jobOutputSecrets: jobID (lowercase) -> outputName (lowercase) -> origin
	// A registered job with no secret-derived outputs is represented by an empty inner map.
	jobOutputSecrets map[string]map[string]string
	pendingOutputs   []pendingSecretJobOutput
}

type pendingSecretJobOutput struct {
	jobID       string
	outputName  string
	outputValue string
}

func NewWorkflowSecretTaintMap() *WorkflowSecretTaintMap {
	return &WorkflowSecretTaintMap{
		jobOutputSecrets: make(map[string]map[string]string),
	}
}

func (m *WorkflowSecretTaintMap) Reset() {
	m.jobOutputSecrets = make(map[string]map[string]string)
	m.pendingOutputs = nil
}

func (m *WorkflowSecretTaintMap) markJobAsRegistered(jobID string) {
	jobID = strings.ToLower(jobID)
	if _, exists := m.jobOutputSecrets[jobID]; !exists {
		m.jobOutputSecrets[jobID] = make(map[string]string)
	}
}

func (m *WorkflowSecretTaintMap) setJobOutputSecret(jobID, outputName, origin string) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)
	if m.jobOutputSecrets[jobID] == nil {
		m.jobOutputSecrets[jobID] = make(map[string]string)
	}
	m.jobOutputSecrets[jobID][outputName] = mergeSecretOrigins(m.jobOutputSecrets[jobID][outputName], origin)
}

func (m *WorkflowSecretTaintMap) IsSecretNeedsOutput(jobID, outputName string) (origin string, registered bool) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)

	outputs, exists := m.jobOutputSecrets[jobID]
	if !exists {
		return "", false
	}
	return outputs[outputName], true
}

// RegisterJobOutputs analyzes job outputs and records outputs that are backed by
// secret-derived step outputs from the same job or secret-derived needs outputs
// from previously registered jobs.
func (m *WorkflowSecretTaintMap) RegisterJobOutputs(jobID string, stepOutputSecrets map[string]map[string]string, outputs map[string]*ast.Output) {
	m.markJobAsRegistered(jobID)

	for outputName, output := range outputs {
		if output == nil || output.Value == nil || output.Value.Value == "" {
			continue
		}
		if origin := m.extractSecretOriginFromValue(output.Value.Value, stepOutputSecrets); origin != "" {
			m.setJobOutputSecret(jobID, outputName, origin)
			continue
		}
		if containsUnregisteredSecretNeedsOutput(output.Value.Value, m) {
			m.pendingOutputs = append(m.pendingOutputs, pendingSecretJobOutput{
				jobID:       jobID,
				outputName:  outputName,
				outputValue: output.Value.Value,
			})
		}
	}
}

func (m *WorkflowSecretTaintMap) ResolvePendingJobOutputs() {
	for {
		if len(m.pendingOutputs) == 0 {
			return
		}
		progressed := false
		remaining := m.pendingOutputs[:0]
		for _, pending := range m.pendingOutputs {
			if origin := m.extractSecretOriginFromValue(pending.outputValue, nil); origin != "" {
				m.setJobOutputSecret(pending.jobID, pending.outputName, origin)
				progressed = true
				continue
			}
			remaining = append(remaining, pending)
		}
		m.pendingOutputs = remaining
		if !progressed {
			return
		}
	}
}

func (m *WorkflowSecretTaintMap) extractSecretOriginFromValue(value string, stepOutputSecrets map[string]map[string]string) string {
	var origins []string
	for _, exprContent := range extractExpressionsFromString(value) {
		path := normalizeStepOutputExprPath(exprContent)
		if path == "" {
			continue
		}
		parts := strings.Split(path, ".")
		if len(parts) < 4 || parts[2] != "outputs" {
			continue
		}

		outputName := strings.Join(parts[3:], ".")
		switch parts[0] {
		case "steps":
			if outputs := stepOutputSecrets[parts[1]]; outputs != nil {
				if origin, ok := outputs[outputName]; ok && origin != "" {
					origins = append(origins, splitSecretOrigins(origin)...)
				}
			}
		case "needs":
			if origin, registered := m.IsSecretNeedsOutput(parts[1], outputName); registered && origin != "" {
				origins = append(origins, splitSecretOrigins(origin)...)
			}
		}
	}
	return joinUniqueSecretOrigins(origins)
}

func (m *WorkflowSecretTaintMap) ResolveFromExprStr(exprStr string) (path, origin string, ok bool) {
	path = normalizeStepOutputExprPath(exprStr)
	if path == "" {
		return "", "", false
	}
	parts := strings.Split(path, ".")
	if len(parts) < 4 || parts[0] != "needs" || parts[2] != "outputs" {
		return "", "", false
	}

	outputName := strings.Join(parts[3:], ".")
	origin, registered := m.IsSecretNeedsOutput(parts[1], outputName)
	if !registered || origin == "" {
		return "", "", false
	}
	return path, origin, true
}

func mergeSecretOrigins(existing, incoming string) string {
	if incoming == "" {
		return existing
	}
	if existing == "" {
		return joinUniqueSecretOrigins(splitSecretOrigins(incoming))
	}
	origins := append(splitSecretOrigins(existing), splitSecretOrigins(incoming)...)
	return joinUniqueSecretOrigins(origins)
}

func splitSecretOrigins(origin string) []string {
	if origin == "" {
		return nil
	}
	parts := strings.Split(origin, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func joinUniqueSecretOrigins(origins []string) string {
	seen := make(map[string]struct{}, len(origins))
	result := make([]string, 0, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		result = append(result, origin)
	}
	return strings.Join(result, ",")
}
