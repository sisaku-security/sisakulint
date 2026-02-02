package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// DependabotGitHubActionsRule checks if dependabot.yaml has github-actions ecosystem configured
// when unpinned actions are detected in the workflow.
type DependabotGitHubActionsRule struct {
	BaseRule
	// workflowPath stores the workflow file path to find the project root
	workflowPath string
	// hasUnpinnedAction tracks if any unpinned action was found
	hasUnpinnedAction bool
	// projectRoot stores the detected project root directory
	projectRoot string
	// alreadyChecked prevents duplicate checks across multiple workflows
	alreadyChecked map[string]bool
}

// NewDependabotGitHubActionsRule creates a new DependabotGitHubActionsRule instance.
// workflowPath is the path to the workflow file being analyzed.
func NewDependabotGitHubActionsRule(workflowPath string) *DependabotGitHubActionsRule {
	rule := &DependabotGitHubActionsRule{
		BaseRule: BaseRule{
			RuleName: "dependabot-github-actions",
			RuleDesc: "Check if dependabot.yaml has github-actions ecosystem configured when unpinned actions are detected",
		},
		workflowPath:   workflowPath,
		alreadyChecked: make(map[string]bool),
	}
	// Find project root from workflow path
	rule.projectRoot = rule.findProjectRoot(workflowPath)
	return rule
}

// dependabotConfig represents the structure of dependabot.yaml
type dependabotConfig struct {
	Version int `yaml:"version"`
	Updates []struct {
		PackageEcosystem string `yaml:"package-ecosystem"`
		Directory        string `yaml:"directory"`
		Schedule         struct {
			Interval string `yaml:"interval"`
		} `yaml:"schedule"`
	} `yaml:"updates"`
}

// actionFullShaPattern checks if the given action ref is pinned to a full length commit SHA
var actionFullShaPattern = regexp.MustCompile(`^.+@([0-9a-f]{40})$`)

// VisitWorkflowPre resets state for a new workflow.
func (rule *DependabotGitHubActionsRule) VisitWorkflowPre(_ *ast.Workflow) error {
	rule.hasUnpinnedAction = false
	return nil
}

// VisitJobPre is a no-op for this rule.
func (rule *DependabotGitHubActionsRule) VisitJobPre(_ *ast.Job) error {
	return nil
}

// VisitJobPost is a no-op for this rule.
func (rule *DependabotGitHubActionsRule) VisitJobPost(_ *ast.Job) error {
	return nil
}

// VisitStep checks if the step uses an action without a full SHA pinning.
func (rule *DependabotGitHubActionsRule) VisitStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		if action.Uses == nil {
			return nil
		}
		usesValue := action.Uses.Value
		// Skip local actions (starting with ./)
		if strings.HasPrefix(usesValue, "./") {
			return nil
		}
		// Skip Docker actions
		if strings.HasPrefix(usesValue, "docker://") {
			return nil
		}
		// Check if the action is pinned to a full SHA
		if !actionFullShaPattern.MatchString(usesValue) {
			rule.hasUnpinnedAction = true
		}
	}
	return nil
}

// VisitWorkflowPost checks dependabot configuration if unpinned actions were found.
func (rule *DependabotGitHubActionsRule) VisitWorkflowPost(_ *ast.Workflow) error {
	if !rule.hasUnpinnedAction {
		return nil
	}

	if rule.projectRoot == "" {
		return nil
	}

	// Avoid duplicate checks for the same project
	if rule.alreadyChecked[rule.projectRoot] {
		return nil
	}
	rule.alreadyChecked[rule.projectRoot] = true

	// Check for dependabot.yaml or dependabot.yml
	dependabotPath := rule.findDependabotFile(rule.projectRoot)

	if dependabotPath == "" {
		// dependabot.yaml does not exist
		rule.Errorf(
			&ast.Position{Line: 1, Col: 1},
			"dependabot.yaml does not exist. Without Dependabot, major version updates (e.g., v3 -> v4) for GitHub Actions won't be automated. "+
				"Create .github/dependabot.yaml with github-actions ecosystem. See https://sisaku-security.github.io/lint/docs/rules/dependabotgithubactionsrule/",
		)
		rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
			return createDependabotFile(rule.projectRoot)
		}))
		return nil
	}

	// dependabot.yaml exists, check if github-actions ecosystem is configured
	hasGitHubActionsEcosystem, err := rule.checkDependabotConfig(dependabotPath)
	if err != nil {
		rule.Debug("failed to parse dependabot config: %v", err)
		return nil
	}

	if !hasGitHubActionsEcosystem {
		rule.Errorf(
			&ast.Position{Line: 1, Col: 1},
			"dependabot.yaml exists but github-actions ecosystem is not configured. "+
				"Without it, major version updates (e.g., v3 -> v4) for GitHub Actions won't be automated. "+
				"See https://sisaku-security.github.io/lint/docs/rules/dependabotgithubactionsrule/",
		)
		rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
			return updateDependabotFile(dependabotPath)
		}))
	}

	return nil
}

// findProjectRoot finds the project root directory by looking for .github directory.
func (rule *DependabotGitHubActionsRule) findProjectRoot(workflowPath string) string {
	// Convert to absolute path if needed
	absPath, err := filepath.Abs(workflowPath)
	if err != nil {
		return ""
	}

	dir := filepath.Dir(absPath)
	for {
		// Check if .github directory exists
		githubDir := filepath.Join(dir, ".github")
		if info, err := os.Stat(githubDir); err == nil && info.IsDir() {
			return dir
		}

		// Move to parent directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}
	return ""
}

// findDependabotFile finds the dependabot configuration file.
func (rule *DependabotGitHubActionsRule) findDependabotFile(projectRoot string) string {
	yamlPath := filepath.Join(projectRoot, ".github", "dependabot.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath
	}

	ymlPath := filepath.Join(projectRoot, ".github", "dependabot.yml")
	if _, err := os.Stat(ymlPath); err == nil {
		return ymlPath
	}

	return ""
}

// checkDependabotConfig checks if the dependabot config has github-actions ecosystem.
func (rule *DependabotGitHubActionsRule) checkDependabotConfig(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var config dependabotConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return false, err
	}

	for _, update := range config.Updates {
		if update.PackageEcosystem == "github-actions" {
			return true, nil
		}
	}

	return false, nil
}

// createDependabotFile creates a new dependabot.yaml file with github-actions ecosystem.
func createDependabotFile(projectRoot string) error {
	path := filepath.Join(projectRoot, ".github", "dependabot.yaml")

	content := `version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`

	return os.WriteFile(path, []byte(content), 0o644)
}

// updateDependabotFile updates existing dependabot.yaml to add github-actions ecosystem.
func updateDependabotFile(dependabotPath string) error {
	data, err := os.ReadFile(dependabotPath)
	if err != nil {
		return err
	}

	// Parse YAML while preserving structure
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}

	// Find the updates array and append github-actions config
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}

	docContent := root.Content[0]
	if docContent.Kind != yaml.MappingNode {
		return nil
	}

	// Find the "updates" key
	for i := 0; i < len(docContent.Content); i += 2 {
		if docContent.Content[i].Value == "updates" {
			updatesNode := docContent.Content[i+1]
			if updatesNode.Kind == yaml.SequenceNode {
				// Create new github-actions entry
				newEntry := &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "package-ecosystem"},
						{Kind: yaml.ScalarNode, Value: "github-actions", Style: yaml.DoubleQuotedStyle},
						{Kind: yaml.ScalarNode, Value: "directory"},
						{Kind: yaml.ScalarNode, Value: "/", Style: yaml.DoubleQuotedStyle},
						{Kind: yaml.ScalarNode, Value: "schedule"},
						{
							Kind: yaml.MappingNode,
							Content: []*yaml.Node{
								{Kind: yaml.ScalarNode, Value: "interval"},
								{Kind: yaml.ScalarNode, Value: "weekly", Style: yaml.DoubleQuotedStyle},
							},
						},
					},
				}
				updatesNode.Content = append(updatesNode.Content, newEntry)
			}
			break
		}
	}

	// Write back
	output, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}

	return os.WriteFile(dependabotPath, output, 0o644)
}
