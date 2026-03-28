package core

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// HasZizmorIgnoreComment checks if a yaml.Node or any of its descendants
// contains a "zizmor: ignore[ruleName]" inline suppression comment.
// This respects the zizmor convention for suppressing findings inline.
// See: https://woodruffw.github.io/zizmor/usage/#inline-ignores
func HasZizmorIgnoreComment(node *yaml.Node, ruleName string) bool {
	if node == nil {
		return false
	}
	pattern := fmt.Sprintf("zizmor: ignore[%s]", ruleName)
	return hasZizmorIgnoreInNode(node, pattern)
}

func hasZizmorIgnoreInNode(node *yaml.Node, pattern string) bool {
	if node == nil {
		return false
	}
	if strings.Contains(node.HeadComment, pattern) ||
		strings.Contains(node.LineComment, pattern) ||
		strings.Contains(node.FootComment, pattern) {
		return true
	}
	for _, child := range node.Content {
		if hasZizmorIgnoreInNode(child, pattern) {
			return true
		}
	}
	return false
}
