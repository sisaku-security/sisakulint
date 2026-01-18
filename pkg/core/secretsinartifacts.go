package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// SecretsInArtifactsRule detects when sensitive information may be included in GitHub Actions artifacts.
// This includes uploading entire repositories (path: .) or using older versions of upload-artifact
// that include hidden files by default.
//
// Based on CodeQL query: https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/
// CWE-312: Cleartext Storage of Sensitive Information
// Security severity: 7.5
type SecretsInArtifactsRule struct {
	BaseRule
}

// NewSecretsInArtifactsRule creates a new secrets-in-artifacts detection rule.
func NewSecretsInArtifactsRule() *SecretsInArtifactsRule {
	return &SecretsInArtifactsRule{
		BaseRule: BaseRule{
			RuleName: "secrets-in-artifacts",
			RuleDesc: "Detects sensitive information that may be included in GitHub Actions artifacts. Uploading entire repositories or using older artifact upload versions can expose secrets like GITHUB_TOKEN or .env files. CWE-312.",
		},
	}
}

// unsafeArtifactPaths contains patterns that indicate potentially dangerous artifact paths.
// These paths may include sensitive files like .git directory, .env files, or entire repository.
var unsafeArtifactPaths = []string{
	".",    // Current directory (entire repository)
	"./",   // Current directory with trailing slash
	"*",    // Everything
	"**",   // Recursive everything
	"**/*", // Recursive everything
}

// sensitivePathPatterns are regex patterns that match paths likely to contain secrets.
var sensitivePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\.git(/.*)?$`),     // .git directory
	regexp.MustCompile(`^\.env(\..*)?$`),    // .env files
	regexp.MustCompile(`^\.npmrc$`),         // npm config with tokens
	regexp.MustCompile(`^\.pypirc$`),        // PyPI config with tokens
	regexp.MustCompile(`credentials\.json`), // Generic credentials file
	regexp.MustCompile(`secrets\..*`),       // Generic secrets files
	regexp.MustCompile(`\.aws(/.*)?$`),      // AWS credentials directory
	regexp.MustCompile(`\.kube(/.*)?$`),     // Kubernetes config
	regexp.MustCompile(`\.ssh(/.*)?$`),      // SSH keys
}

// isUnsafeArtifactPath checks if the path might expose sensitive files.
func isUnsafeArtifactPath(path string) bool {
	path = strings.TrimSpace(path)

	// Check for exact matches of dangerous paths
	for _, unsafePath := range unsafeArtifactPaths {
		if path == unsafePath {
			return true
		}
	}

	return false
}

// containsSensitivePath checks if any path in a multi-line path spec directly references sensitive files.
// This only checks for explicit sensitive file patterns (e.g., .git, .env), NOT broad paths like "." or "**".
func containsSensitivePath(pathSpec string) bool {
	// Split by newlines for multi-line path specs
	lines := strings.Split(pathSpec, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Check if line matches sensitive file patterns (e.g., .git, .env, .aws)
		for _, pattern := range sensitivePathPatterns {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

// extractMajorVersion extracts the major version number from a version string.
// Returns -1 if not a semantic version.
func extractMajorVersion(version string) int {
	// Handle commit SHA (both full 40-char and short 7+ char hex strings)
	if len(version) >= 7 && len(version) <= 40 && isHexString(version) {
		return -1 // Can't determine version from SHA
	}

	// Handle v1, v2, v3, v4 format
	version = strings.TrimPrefix(version, "v")

	// Get first number
	var majorStr string
	for _, c := range version {
		if c >= '0' && c <= '9' {
			majorStr += string(c)
		} else {
			break
		}
	}

	if majorStr == "" {
		return -1
	}

	var major int
	for _, c := range majorStr {
		major = major*10 + int(c-'0')
	}
	return major
}

// isHexString checks if a string is a valid hexadecimal string.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseActionVersion extracts the version part from an action uses string.
// e.g., "actions/upload-artifact@v4" -> "v4"
func parseActionVersion(uses string) string {
	idx := strings.LastIndex(uses, "@")
	if idx == -1 {
		return ""
	}
	return uses[idx+1:]
}

func (rule *SecretsInArtifactsRule) VisitStep(node *ast.Step) error {
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	// Check if this is upload-artifact action
	if !strings.HasPrefix(uses, "actions/upload-artifact@") {
		return nil
	}

	// Extract version
	version := parseActionVersion(uses)
	majorVersion := extractMajorVersion(version)

	// Get path input
	var pathValue string
	var hasPath bool
	if pathInput, exists := action.Inputs["path"]; exists && pathInput != nil && pathInput.Value != nil {
		pathValue = pathInput.Value.Value
		hasPath = true
	}

	// Check for unsafe conditions

	// Case 1: path explicitly includes sensitive file patterns (e.g., .git, .env)
	if hasPath && containsSensitivePath(pathValue) {
		rule.Errorf(
			node.Pos,
			"secrets exposure risk: artifact upload path %q may include sensitive files. Avoid uploading directories that might contain credentials or tokens. See https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/",
			pathValue,
		)
		// No auto-fix for this case as user may have intentional reasons
		return nil
	}

	// Case 3: Using v3 or earlier (hidden files included by default)
	// In v4+, include-hidden-files defaults to false
	if majorVersion > 0 && majorVersion < 4 {
		// Check if include-hidden-files is explicitly set to false (safe)
		if hiddenInput, exists := action.Inputs["include-hidden-files"]; exists && hiddenInput != nil && hiddenInput.Value != nil {
			if hiddenInput.Value.Value == "false" {
				// Explicitly disabled, this is safe
				return nil
			}
		}

		// v3 and earlier include hidden files by default
		rule.Errorf(
			node.Pos,
			"secrets exposure risk: actions/upload-artifact@%s includes hidden files by default. This can expose .git directory containing GITHUB_TOKEN. Upgrade to v4+ or explicitly set 'include-hidden-files: false'. See https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/",
			version,
		)
		rule.AddAutoFixer(NewStepFixer(node, rule))
	}

	// Case 4: v4+ with include-hidden-files: true and path: . is dangerous
	if majorVersion >= 4 {
		if hiddenInput, exists := action.Inputs["include-hidden-files"]; exists && hiddenInput != nil && hiddenInput.Value != nil {
			if hiddenInput.Value.Value == "true" && hasPath && isUnsafeArtifactPath(pathValue) {
				rule.Errorf(
					node.Pos,
					"secrets exposure risk: artifact upload with 'include-hidden-files: true' and path %q may expose sensitive files. Remove 'include-hidden-files: true' or use a specific directory. See https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/",
					pathValue,
				)
				rule.AddAutoFixer(NewStepFixer(node, rule))
			}
		}
	}

	return nil
}

// FixStep attempts to fix the unsafe artifact upload configuration.
// For v3 and earlier, adds include-hidden-files: false.
// For v4+ with include-hidden-files: true, sets it to false.
func (rule *SecretsInArtifactsRule) FixStep(node *ast.Step) error {
	action := node.Exec.(*ast.ExecAction)

	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	// Determine the fix based on the issue
	version := parseActionVersion(action.Uses.Value)
	majorVersion := extractMajorVersion(version)

	// For v3 and earlier, add include-hidden-files: false
	if majorVersion > 0 && majorVersion < 4 {
		action.Inputs["include-hidden-files"] = &ast.Input{
			Name: &ast.String{
				Value: "include-hidden-files",
				Pos:   node.Pos,
			},
			Value: &ast.String{
				Value: "false",
				Pos:   node.Pos,
			},
		}
		addInputToWithSection(node.BaseNode, "include-hidden-files", "false")
		return nil
	}

	// For v4+ with include-hidden-files: true, set it to false
	if majorVersion >= 4 {
		if hiddenInput, exists := action.Inputs["include-hidden-files"]; exists && hiddenInput != nil && hiddenInput.Value != nil {
			if hiddenInput.Value.Value == "true" {
				hiddenInput.Value.Value = "false"
				addInputToWithSection(node.BaseNode, "include-hidden-files", "false")
			}
		}
	}

	return nil
}

// addInputToWithSection adds or updates an input in the with section of a step node.
func addInputToWithSection(stepNode *yaml.Node, key, value string) {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return
	}

	// Find the 'with' section
	withIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "with" {
			withIndex = i
			break
		}
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valueNode := &yaml.Node{Kind: yaml.ScalarNode, Value: value}

	if withIndex >= 0 {
		// 'with' section exists, add or update the key
		withNode := stepNode.Content[withIndex+1]
		if withNode.Kind == yaml.MappingNode {
			// Check if key already exists
			for i := 0; i < len(withNode.Content); i += 2 {
				if withNode.Content[i].Value == key {
					// Update existing value
					withNode.Content[i+1] = valueNode
					return
				}
			}
			// Add new entry
			withNode.Content = append(withNode.Content, keyNode, valueNode)
		}
		return
	}

	// 'with' section doesn't exist, create it after 'uses'
	usesIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "uses" {
			usesIndex = i
			break
		}
	}

	withKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "with"}
	withValue := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{keyNode, valueNode},
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
