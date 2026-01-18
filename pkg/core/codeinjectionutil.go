package core

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// AddEnvVarsToStepNode adds environment variables to a step's YAML node (BaseNode)
// This ensures that when the YAML is re-encoded, the env: section appears in the output
func AddEnvVarsToStepNode(stepNode *yaml.Node, envVars map[string]string) error {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return fmt.Errorf("step node must be a mapping node")
	}

	// Find or create 'env' section
	envIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == AvailableEnv {
			envIndex = i
			break
		}
	}

	var envNode *yaml.Node
	if envIndex == -1 {
		// Create new env section
		envKey := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "env",
		}
		envNode = &yaml.Node{
			Kind:    yaml.MappingNode,
			Content: []*yaml.Node{},
		}
		stepNode.Content = append(stepNode.Content, envKey, envNode)
	} else {
		// Use existing env section
		envNode = stepNode.Content[envIndex+1]
		if envNode.Kind != yaml.MappingNode {
			return fmt.Errorf("env node must be a mapping node")
		}
	}

	// Add each environment variable
	for envVarName, envVarValue := range envVars {
		// Check if this env var already exists
		exists := false
		for i := 0; i < len(envNode.Content); i += 2 {
			if envNode.Content[i].Value == envVarName {
				// Update existing value
				envNode.Content[i+1].Value = envVarValue
				exists = true
				break
			}
		}

		if !exists {
			// Add new env var
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: envVarName,
			}
			valueNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: envVarValue,
			}
			envNode.Content = append(envNode.Content, keyNode, valueNode)
		}
	}

	return nil
}

// ReplaceInRunScript replaces expressions in a run: script within the step's YAML node
func ReplaceInRunScript(stepNode *yaml.Node, replacements map[string]string) error {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return fmt.Errorf("step node must be a mapping node")
	}

	// Find 'run' section
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMRun {
			runNode := stepNode.Content[i+1]
			if runNode.Kind == yaml.ScalarNode {
				// Apply all replacements
				for oldExpr, newExpr := range replacements {
					runNode.Value = strings.ReplaceAll(runNode.Value, oldExpr, newExpr)
				}
			}
			return nil
		}
	}

	return fmt.Errorf("run section not found in step node")
}

// ReplaceInGitHubScript replaces expressions in a script: input of actions/github-script
func ReplaceInGitHubScript(stepNode *yaml.Node, replacements map[string]string) error {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return fmt.Errorf("step node must be a mapping node")
	}

	// Find 'with' section
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "with" {
			withNode := stepNode.Content[i+1]
			if withNode.Kind != yaml.MappingNode {
				return fmt.Errorf("with node must be a mapping node")
			}

			// Find 'script' within 'with'
			for j := 0; j < len(withNode.Content); j += 2 {
				if withNode.Content[j].Value == "script" {
					scriptNode := withNode.Content[j+1]
					if scriptNode.Kind == yaml.ScalarNode {
						// Apply all replacements
						for oldExpr, newExpr := range replacements {
							scriptNode.Value = strings.ReplaceAll(scriptNode.Value, oldExpr, newExpr)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("script field not found in with section")
		}
	}

	return fmt.Errorf("with section not found in step node")
}
