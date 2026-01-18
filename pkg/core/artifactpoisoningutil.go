package core

import "gopkg.in/yaml.v3"

// UntrustedTriggers defines workflow triggers that may execute with untrusted input.
// These triggers are commonly associated with security risks in CI/CD pipelines:
// - workflow_run: Triggered by completion of another workflow (may be from PR)
// - pull_request_target: Runs in the context of the base branch but with PR info
// - issue_comment: Triggered by comments which can be from external contributors
var UntrustedTriggers = map[string]bool{
	"workflow_run":        true,
	"pull_request_target": true,
	"issue_comment":       true,
}

// AddPathToWithSection adds or updates the path input in the with section of a step node.
// This is used by artifact poisoning rules to add safe extraction paths.
// The path will be set to "${{ runner.temp }}/artifacts" if not already present or unsafe.
func AddPathToWithSection(stepNode *yaml.Node, path string) {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return
	}

	// Find the 'with' section
	withIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMWith {
			withIndex = i
			break
		}
	}

	pathKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "path"}
	pathValue := &yaml.Node{Kind: yaml.ScalarNode, Value: path}

	if withIndex >= 0 {
		// 'with' section exists, add or update 'path'
		withNode := stepNode.Content[withIndex+1]
		if withNode.Kind == yaml.MappingNode {
			// Check if path already exists
			for i := 0; i < len(withNode.Content); i += 2 {
				if withNode.Content[i].Value == SBOMPath {
					// Update existing path (overwrite unsafe path)
					withNode.Content[i+1] = pathValue
					return
				}
			}
			// Add new path entry
			withNode.Content = append(withNode.Content, pathKey, pathValue)
		}
		return
	}

	// 'with' section doesn't exist, create it after 'uses'
	usesIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMUses {
			usesIndex = i
			break
		}
	}

	withKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "with"}
	withValue := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{pathKey, pathValue},
	}

	if usesIndex >= 0 {
		// Insert 'with' section after 'uses'
		insertIndex := usesIndex + 2
		stepNode.Content = append(
			stepNode.Content[:insertIndex],
			append([]*yaml.Node{withKey, withValue}, stepNode.Content[insertIndex:]...)...,
		)
	} else {
		// 'uses' not found, append at the end
		stepNode.Content = append(stepNode.Content, withKey, withValue)
	}
}
