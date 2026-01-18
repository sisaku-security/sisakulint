package core

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// checkoutVersionPattern is compiled once at package level for performance.
var checkoutVersionPattern = regexp.MustCompile(`^v?(\d+)`)

// persistCredentialsKey is the input key for persist-credentials in checkout action.
const persistCredentialsKey = "persist-credentials"

// ArtipackedRule detects credential persistence vulnerabilities in GitHub Actions workflows.
// When actions/checkout retains credentials (persist-credentials: true, which is the default),
// the GITHUB_TOKEN is stored in .git/config. If a subsequent actions/upload-artifact uploads
// the workspace (e.g., path: "."), this token can be leaked.
//
// Detection conditions:
// 1. actions/checkout step without persist-credentials: false
// 2. actions/upload-artifact step with dangerous path patterns (., ./, .., ${{ github.workspace }})
//
// Severity levels:
// - High: checkout < v6 + dangerous upload (credentials in .git/config)
// - Medium: checkout >= v6 + dangerous upload (credentials in $RUNNER_TEMP)
// - Low/Medium: checkout without dangerous upload (potential risk)
//
// References:
// - https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
// - zizmor: https://github.com/woodruffw/zizmor/blob/main/crates/zizmor/src/audit/artipacked.rs
type ArtipackedRule struct {
	BaseRule
	// checkoutSteps stores checkout steps without persist-credentials: false per job
	checkoutSteps []*checkoutInfo
	// currentJobID stores the current job being processed
	currentJobID string
}

type checkoutInfo struct {
	step    *ast.Step
	version int // 0 = unknown, 6+ = v6 or later
}

func NewArtipackedRule() *ArtipackedRule {
	return &ArtipackedRule{
		BaseRule: BaseRule{
			RuleName: "artipacked",
			RuleDesc: "Detects credential leakage risk when actions/checkout credentials are persisted and workspace is uploaded via actions/upload-artifact",
		},
	}
}

func (rule *ArtipackedRule) VisitWorkflowPre(n *ast.Workflow) error {
	rule.checkoutSteps = nil
	rule.currentJobID = ""
	return nil
}

func (rule *ArtipackedRule) VisitWorkflowPost(n *ast.Workflow) error {
	rule.checkoutSteps = nil
	rule.currentJobID = ""
	return nil
}

func (rule *ArtipackedRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutSteps = nil
	if node.ID != nil {
		rule.currentJobID = node.ID.Value
	}
	return nil
}

func (rule *ArtipackedRule) VisitJobPost(node *ast.Job) error {
	for _, info := range rule.checkoutSteps {
		severity := "Medium"
		if info.version >= 6 {
			severity = "Low"
		}
		rule.Errorf(
			info.step.Pos,
			"[%s] actions/checkout without 'persist-credentials: false' at step %q. Credentials are stored in %s. While no dangerous upload-artifact was found in this job, consider adding 'persist-credentials: false' to prevent credential exposure. "+
				"See https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
			severity,
			info.step.String(),
			rule.getCredentialLocation(info.version),
		)
		rule.AddAutoFixer(NewStepFixer(info.step, rule))
	}
	rule.checkoutSteps = nil
	return nil
}

func (rule *ArtipackedRule) getCredentialLocation(version int) string {
	if version >= 6 {
		return "$RUNNER_TEMP"
	}
	return ".git/config"
}

func (rule *ArtipackedRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if rule.isCheckoutAction(action.Uses.Value) {
		rule.handleCheckout(step, action)
		return nil
	}

	if rule.isUploadArtifactAction(action.Uses.Value) {
		rule.handleUploadArtifact(step, action)
	}

	return nil
}

func (rule *ArtipackedRule) isCheckoutAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/checkout@")
}

func (rule *ArtipackedRule) isUploadArtifactAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/upload-artifact@")
}

func (rule *ArtipackedRule) handleCheckout(step *ast.Step, action *ast.ExecAction) {
	if action.Inputs != nil {
		if persistCreds, exists := action.Inputs[persistCredentialsKey]; exists {
			if persistCreds.Value != nil && strings.ToLower(persistCreds.Value.Value) == "false" {
				return
			}
		}
	}

	version := rule.getCheckoutVersion(action.Uses.Value)

	rule.checkoutSteps = append(rule.checkoutSteps, &checkoutInfo{
		step:    step,
		version: version,
	})
}

func (rule *ArtipackedRule) getCheckoutVersion(uses string) int {
	parts := strings.Split(uses, "@")
	if len(parts) != 2 {
		return 0
	}

	matches := checkoutVersionPattern.FindStringSubmatch(parts[1])
	if len(matches) >= 2 {
		major, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0
		}
		return major
	}

	return 0
}

func (rule *ArtipackedRule) handleUploadArtifact(step *ast.Step, action *ast.ExecAction) {
	pathValue := rule.getUploadPath(action)
	if !rule.isDangerousUploadPath(pathValue) {
		return
	}

	if len(rule.checkoutSteps) == 0 {
		return
	}

	for _, checkoutInfo := range rule.checkoutSteps {
		severity := "High"
		if checkoutInfo.version >= 6 {
			severity = "Medium"
		}

		rule.Errorf(
			step.Pos,
			"[%s] actions/upload-artifact uploads workspace with path %q, which may include credentials from actions/checkout at line %d. "+
				"The checkout action stores GITHUB_TOKEN in %s. "+
				"Add 'persist-credentials: false' to the checkout step or avoid uploading the entire workspace. "+
				"See https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
			severity,
			pathValue,
			checkoutInfo.step.Pos.Line,
			rule.getCredentialLocation(checkoutInfo.version),
		)

		rule.AddAutoFixer(NewStepFixer(checkoutInfo.step, rule))
	}

	rule.checkoutSteps = nil
}

func (rule *ArtipackedRule) getUploadPath(action *ast.ExecAction) string {
	if action.Inputs == nil {
		return ""
	}

	pathInput, exists := action.Inputs["path"]
	if !exists || pathInput == nil || pathInput.Value == nil {
		return ""
	}

	return pathInput.Value.Value
}

func (rule *ArtipackedRule) isDangerousUploadPath(path string) bool {
	if path == "" {
		return false
	}

	path = strings.TrimSpace(path)

	// Current directory patterns
	if path == "." || path == "./" {
		return true
	}
	// Parent directory patterns
	if path == ".." || strings.HasPrefix(path, "../") {
		return true
	}
	// GitHub workspace variable patterns
	if strings.Contains(path, "github.workspace") || strings.Contains(path, "GITHUB_WORKSPACE") {
		return true
	}
	// Glob patterns that could match the entire workspace
	if path == "*" || path == "**" || path == "**/*" || path == "./**" || path == "./**/*" {
		return true
	}

	return false
}

func (rule *ArtipackedRule) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "step is not an action")
	}

	if !rule.isCheckoutAction(action.Uses.Value) {
		return FormattedError(step.Pos, rule.RuleName, "not a checkout action")
	}

	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	action.Inputs[persistCredentialsKey] = &ast.Input{
		Name: &ast.String{
			Value: persistCredentialsKey,
			Pos:   step.Pos,
		},
		Value: &ast.String{
			Value: "false",
			Pos:   step.Pos,
		},
	}

	rule.addPersistCredentialsToWithSection(step.BaseNode)
	return nil
}

func (rule *ArtipackedRule) addPersistCredentialsToWithSection(stepNode *yaml.Node) {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return
	}

	withIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMWith {
			withIndex = i
			break
		}
	}

	persistKey := &yaml.Node{Kind: yaml.ScalarNode, Value: persistCredentialsKey}
	persistValue := &yaml.Node{Kind: yaml.ScalarNode, Value: "false"}

	if withIndex >= 0 {
		withNode := stepNode.Content[withIndex+1]
		if withNode.Kind == yaml.MappingNode {
			for i := 0; i < len(withNode.Content); i += 2 {
				if withNode.Content[i].Value == persistCredentialsKey {
					withNode.Content[i+1] = persistValue
					return
				}
			}
			withNode.Content = append([]*yaml.Node{persistKey, persistValue}, withNode.Content...)
		}
		return
	}

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
		Content: []*yaml.Node{persistKey, persistValue},
	}

	if usesIndex >= 0 {
		insertIndex := usesIndex + 2
		stepNode.Content = append(
			stepNode.Content[:insertIndex],
			append([]*yaml.Node{withKey, withValue}, stepNode.Content[insertIndex:]...)...,
		)
	} else {
		stepNode.Content = append(stepNode.Content, withKey, withValue)
	}
}
