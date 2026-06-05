package core

import (
	"fmt"
	"sort"
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
				runNode.Value = applyStringReplacements(runNode.Value, replacements)
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
						scriptNode.Value = applyGitHubScriptReplacements(scriptNode.Value, replacements)
					}
					return nil
				}
			}
			return fmt.Errorf("script field not found in with section")
		}
	}

	return fmt.Errorf("with section not found in step node")
}

func applyStringReplacements(value string, replacements map[string]string) string {
	keys := sortedReplacementKeys(replacements)
	return applyStringReplacementsWithKeys(value, replacements, keys)
}

func applyStringReplacementsWithKeys(value string, replacements map[string]string, keys []string) string {
	for _, oldExpr := range keys {
		value = strings.ReplaceAll(value, oldExpr, replacements[oldExpr])
	}
	return value
}

func sortedReplacementKeys(replacements map[string]string) []string {
	keys := make([]string, 0, len(replacements))
	for oldExpr := range replacements {
		keys = append(keys, oldExpr)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	return keys
}

func applyGitHubScriptReplacements(value string, replacements map[string]string) string {
	if len(replacements) == 0 || value == "" {
		return value
	}

	keys := sortedReplacementKeys(replacements)
	var builder strings.Builder
	last := 0

	for i := 0; i < len(value); {
		if i+1 < len(value) && value[i] == '/' {
			if value[i+1] == '/' {
				end := findJSLineCommentEnd(value, i+2)
				builder.WriteString(applyStringReplacementsWithKeys(value[last:i], replacements, keys))
				builder.WriteString(applyStringReplacementsWithKeys(value[i:end], replacements, keys))
				i = end
				last = i
				continue
			}
			if value[i+1] == '*' {
				end := findJSBlockCommentEnd(value, i+2)
				builder.WriteString(applyStringReplacementsWithKeys(value[last:i], replacements, keys))
				builder.WriteString(applyStringReplacementsWithKeys(value[i:end], replacements, keys))
				i = end
				last = i
				continue
			}
		}

		quote := value[i]
		if quote != '\'' && quote != '"' && quote != '`' {
			i++
			continue
		}

		end, ok := findJSStringLiteralEnd(value, i, quote)
		if !ok {
			i++
			continue
		}

		builder.WriteString(applyStringReplacementsWithKeys(value[last:i], replacements, keys))

		content := value[i+1 : end]
		if rewritten, changed := rewriteGitHubScriptStringLiteral(content, quote, replacements, keys); changed {
			builder.WriteString(rewritten)
		} else {
			builder.WriteString(value[i : end+1])
		}

		i = end + 1
		last = i
	}

	if last == 0 {
		return applyStringReplacementsWithKeys(value, replacements, keys)
	}

	builder.WriteString(applyStringReplacementsWithKeys(value[last:], replacements, keys))
	return builder.String()
}

func findJSLineCommentEnd(value string, start int) int {
	for i := start; i < len(value); i++ {
		if value[i] == '\n' || value[i] == '\r' {
			return i
		}
	}
	return len(value)
}

func findJSBlockCommentEnd(value string, start int) int {
	if end := strings.Index(value[start:], "*/"); end >= 0 {
		return start + end + len("*/")
	}
	return len(value)
}

func findJSStringLiteralEnd(value string, start int, quote byte) (int, bool) {
	for i := start + 1; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			continue
		}
		if value[i] == quote {
			return i, true
		}
	}
	return 0, false
}

type githubScriptLiteralPart struct {
	value        string
	isExpression bool
}

func rewriteGitHubScriptStringLiteral(content string, quote byte, replacements map[string]string, keys []string) (string, bool) {
	parts, changed := splitGitHubScriptStringLiteral(content, replacements, keys)
	if !changed {
		return "", false
	}

	terms := make([]string, 0, len(parts))
	for _, part := range parts {
		if part.value == "" {
			continue
		}
		if part.isExpression {
			terms = append(terms, part.value)
			continue
		}
		terms = append(terms, quoteJSStringSegment(part.value, quote))
	}
	if len(terms) == 0 {
		return "", false
	}

	return strings.Join(terms, " + "), true
}

func splitGitHubScriptStringLiteral(content string, replacements map[string]string, keys []string) ([]githubScriptLiteralPart, bool) {
	parts := make([]githubScriptLiteralPart, 0)
	segmentStart := 0
	changed := false

	for i := 0; i < len(content); {
		matchedKey := ""
		for _, key := range keys {
			if strings.HasPrefix(content[i:], key) {
				matchedKey = key
				break
			}
		}

		if matchedKey == "" {
			i++
			continue
		}

		if segmentStart < i {
			parts = append(parts, githubScriptLiteralPart{value: content[segmentStart:i]})
		}
		parts = append(parts, githubScriptLiteralPart{
			value:        replacements[matchedKey],
			isExpression: true,
		})
		i += len(matchedKey)
		segmentStart = i
		changed = true
	}

	if !changed {
		return nil, false
	}
	if segmentStart < len(content) {
		parts = append(parts, githubScriptLiteralPart{value: content[segmentStart:]})
	}

	return parts, true
}

func quoteJSStringSegment(value string, quote byte) string {
	return string(quote) + value + string(quote)
}
