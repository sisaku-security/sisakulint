package core

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// DependabotEcosystemRule detects package ecosystems (npm/gomod/pip/cargo/bundler/composer/
// maven/gradle) inferred from root-level lockfiles and workflow setup actions that are
// missing from the dependabot configuration. The github-actions ecosystem is intentionally
// out of scope (handled by DependabotGitHubActionsRule). Local-scan only; diagnose-only.
type DependabotEcosystemRule struct {
	BaseRule
	workflowPath string
	isRemote     bool
	projectRoot  string
	// setupActionReqs collects ecosystem requirements derived from setup actions in the
	// current workflow, anchored to the step position for precise reporting.
	setupActionReqs []ecosystemRequirement
}

// ecosystemRequirement represents a detected need for one or more dependabot ecosystems.
// accepts has size 1 for unambiguous signals and size 2 for ambiguous ones (setup-java
// implies {maven, gradle}). pos is the anchor for the warning; nil means project-level
// (Position{1,1}).
type ecosystemRequirement struct {
	accepts []string
	label   string
	pos     *ast.Position
}

// NewDependabotEcosystemRule creates the rule. workflowPath is the analyzed workflow file
// path. When isRemote is true the local filesystem is not consulted.
func NewDependabotEcosystemRule(workflowPath string, isRemote bool) *DependabotEcosystemRule {
	rule := &DependabotEcosystemRule{
		BaseRule: BaseRule{
			RuleName: "dependabot-ecosystem",
			RuleDesc: "Check if dependabot config covers package ecosystems detected from lockfiles and setup actions",
		},
		workflowPath: workflowPath,
		isRemote:     isRemote,
	}
	if !isRemote {
		rule.projectRoot = dependabotFindProjectRoot(workflowPath)
	}
	return rule
}

// lockfileEcosystems maps a root-level lockfile name to the dependabot ecosystem it implies.
var lockfileEcosystems = []struct {
	file      string
	ecosystem string
}{
	{"package-lock.json", "npm"},
	{"pnpm-lock.yaml", "npm"},
	{"yarn.lock", "npm"},
	{"go.sum", "gomod"},
	{"Cargo.lock", "cargo"},
	{"Gemfile.lock", "bundler"},
	{"composer.lock", "composer"},
	{"Pipfile.lock", "pip"},
	{"poetry.lock", "pip"},
	{"requirements.txt", "pip"},
	{"pom.xml", "maven"},
	{"build.gradle", "gradle"},
	{"build.gradle.kts", "gradle"},
	{"gradle.lockfile", "gradle"},
}

// VisitWorkflowPre resets per-workflow state.
func (rule *DependabotEcosystemRule) VisitWorkflowPre(_ *ast.Workflow) error {
	rule.setupActionReqs = nil
	return nil
}

// VisitJobPre is a no-op for this rule.
func (rule *DependabotEcosystemRule) VisitJobPre(_ *ast.Job) error { return nil }

// VisitJobPost is a no-op for this rule.
func (rule *DependabotEcosystemRule) VisitJobPost(_ *ast.Job) error { return nil }

// VisitStep is a no-op until setup-action detection is added in a later task.
func (rule *DependabotEcosystemRule) VisitStep(_ *ast.Step) error { return nil }

// VisitWorkflowPost collects ecosystem requirements from root lockfiles and the workflow's
// setup actions, then warns for each requirement not satisfied by the dependabot config.
func (rule *DependabotEcosystemRule) VisitWorkflowPost(_ *ast.Workflow) error {
	if rule.isRemote {
		rule.Debug("skipping dependabot-ecosystem check in remote scan mode (path: %s)", rule.workflowPath)
		return nil
	}
	if rule.projectRoot == "" {
		return nil
	}

	var reqs []ecosystemRequirement
	for _, lf := range lockfileEcosystems {
		if _, err := os.Stat(filepath.Join(rule.projectRoot, lf.file)); err == nil {
			reqs = append(reqs, ecosystemRequirement{accepts: []string{lf.ecosystem}, label: lf.file})
		}
	}
	reqs = append(reqs, rule.setupActionReqs...)
	if len(reqs) == 0 {
		return nil
	}

	configured := map[string]bool{}
	if configPath := dependabotFindConfigFile(rule.projectRoot); configPath != "" {
		eco, err := dependabotConfiguredEcosystems(configPath)
		if err != nil {
			rule.Debug("failed to parse dependabot config: %v", err)
			return nil
		}
		configured = eco
	}

	seen := map[string]bool{}
	for _, req := range reqs {
		if requirementSatisfied(req, configured) {
			continue
		}
		key := strings.Join(req.accepts, "|")
		if seen[key] {
			continue
		}
		seen[key] = true

		pos := req.pos
		if pos == nil {
			pos = &ast.Position{Line: 1, Col: 1}
		}
		rule.Errorf(
			pos,
			"package ecosystem %q is used (detected from %s) but not configured in dependabot. "+
				"Add a package-ecosystem entry to .github/dependabot.yaml so dependency updates are automated. "+
				"See https://sisaku-security.github.io/lint/docs/rules/dependabotecosystemrule/",
			strings.Join(req.accepts, " or "),
			req.label,
		)
	}
	return nil
}

// requirementSatisfied reports whether the dependabot config covers the requirement, i.e.
// configured contains any of the requirement's accepted ecosystems.
func requirementSatisfied(req ecosystemRequirement, configured map[string]bool) bool {
	for _, eco := range req.accepts {
		if configured[eco] {
			return true
		}
	}
	return false
}
