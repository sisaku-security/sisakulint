package core

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHasZizmorIgnoreComment(t *testing.T) {
	tests := []struct {
		name     string
		node     *yaml.Node
		ruleName string
		expected bool
	}{
		{
			name:     "nil node returns false",
			node:     nil,
			ruleName: "artipacked",
			expected: false,
		},
		{
			name: "LineComment matches rule",
			node: &yaml.Node{
				Kind:        yaml.ScalarNode,
				Value:       "true",
				LineComment: "# zizmor: ignore[artipacked]",
			},
			ruleName: "artipacked",
			expected: true,
		},
		{
			name: "HeadComment matches rule",
			node: &yaml.Node{
				Kind:        yaml.ScalarNode,
				Value:       "true",
				HeadComment: "# zizmor: ignore[cache-poisoning]",
			},
			ruleName: "cache-poisoning",
			expected: true,
		},
		{
			name: "FootComment matches rule",
			node: &yaml.Node{
				Kind:        yaml.ScalarNode,
				Value:       "true",
				FootComment: "# zizmor: ignore[permissions]",
			},
			ruleName: "permissions",
			expected: true,
		},
		{
			name: "comment for different rule does not match",
			node: &yaml.Node{
				Kind:        yaml.ScalarNode,
				Value:       "true",
				LineComment: "# zizmor: ignore[cache-poisoning]",
			},
			ruleName: "artipacked",
			expected: false,
		},
		{
			name: "child node comment matches",
			node: &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "persist-credentials"},
					{
						Kind:        yaml.ScalarNode,
						Value:       "true",
						LineComment: "# zizmor: ignore[artipacked]",
					},
				},
			},
			ruleName: "artipacked",
			expected: true,
		},
		{
			name: "no ignore comment returns false",
			node: &yaml.Node{
				Kind:        yaml.ScalarNode,
				Value:       "true",
				LineComment: "# some other comment",
			},
			ruleName: "artipacked",
			expected: false,
		},
		{
			name: "empty node returns false",
			node: &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: "true",
			},
			ruleName: "artipacked",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasZizmorIgnoreComment(tt.node, tt.ruleName)
			if got != tt.expected {
				t.Errorf("HasZizmorIgnoreComment() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestArtipackedRule_ZizmorIgnoreComment(t *testing.T) {
	// Simulate a step YAML node with zizmor: ignore[artipacked] comment on persist-credentials value
	stepNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "uses"},
			{Kind: yaml.ScalarNode, Value: "actions/checkout@v6"},
			{Kind: yaml.ScalarNode, Value: "with"},
			{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "persist-credentials"},
					{
						Kind:        yaml.ScalarNode,
						Value:       "true",
						LineComment: "# zizmor: ignore[artipacked]",
					},
				},
			},
		},
	}

	if !HasZizmorIgnoreComment(stepNode, "artipacked") {
		t.Error("Expected zizmor ignore comment to be found in nested step node")
	}

	if HasZizmorIgnoreComment(stepNode, "cache-poisoning") {
		t.Error("Expected zizmor ignore comment NOT to be found for different rule")
	}
}
