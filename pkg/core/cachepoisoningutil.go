package core

import (
	"strings"

	"gopkg.in/yaml.v3"
)

var unsafeTriggerNames = map[string]bool{
	"issue_comment":       true,
	"pull_request_target": true,
	"workflow_run":        true,
}

var unsafePatternsLower = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.head_ref",
	"refs/pull/",
	".head_sha", // Detects steps.*.outputs.head_sha
	".head_ref", // Detects steps.*.outputs.head_ref
	".head.sha", // Detects nested head.sha patterns
	".head.ref", // Detects nested head.ref patterns
	"head-sha",  // Detects kebab-case variants
	"head-ref",  // Detects kebab-case variants
}

// Patterns that are explicitly safe to use with any trigger
var safePatternsLower = []string{
	"github.ref",
	"github.sha",
	"github.base_ref",
	"github.event.repository.default_branch",
	"github.event.pull_request.base.ref",
	"github.event.pull_request.base.sha",
}

// IsUnsafeTrigger checks if the trigger event is unsafe for cache poisoning detection.
func IsUnsafeTrigger(eventName string) bool {
	return unsafeTriggerNames[eventName]
}

// IsUnsafeCheckoutRef checks if the ref input contains patterns that indicate
// checking out untrusted PR code. Case-insensitive matching prevents bypass attempts.
// This implements a conservative approach: with untrusted triggers, any ref expression
// is considered unsafe unless it's explicitly known to be safe.
func IsUnsafeCheckoutRef(refValue string) bool {
	if refValue == "" {
		return false
	}

	lower := strings.ToLower(refValue)

	// First, check for known unsafe patterns
	for _, pattern := range unsafePatternsLower {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Conservative approach: if the ref contains an expression (${{...}}),
	// check if it's a known safe pattern
	if strings.Contains(lower, "${{") {
		// Check if it's explicitly safe
		for _, safe := range safePatternsLower {
			if strings.Contains(lower, safe) {
				return false
			}
		}
		// Unknown expression - could be unsafe (e.g., steps.*.outputs.*)
		// We treat it as potentially unsafe to avoid false negatives
		return true
	}

	return false
}

// RemoveRefFromWith removes the "ref" key from the "with" section of a YAML step node.
// This is used by cache poisoning rules to fix unsafe checkout refs.
func RemoveRefFromWith(stepNode *yaml.Node) error {
	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == SBOMWith && val.Kind == yaml.MappingNode {
			newContent := make([]*yaml.Node, 0, len(val.Content))
			for j := 0; j < len(val.Content); j += 2 {
				if j+1 >= len(val.Content) {
					break
				}
				withKey := val.Content[j]
				if withKey.Value != "ref" {
					newContent = append(newContent, val.Content[j], val.Content[j+1])
				}
			}
			if len(newContent) == 0 {
				stepNode.Content = append(stepNode.Content[:i], stepNode.Content[i+2:]...)
			} else {
				val.Content = newContent
			}
			return nil
		}
	}
	return nil
}
