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
// accepts has size 1 for unambiguous signals and is larger for ambiguous ones (setup-java
// implies {maven, gradle, sbt}). pos is the anchor for the warning; nil means project-level
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

// setupActionEcosystems maps a setup-action `uses` prefix to the ecosystems it implies.
// setup-java is ambiguous and is satisfied by maven, gradle, or sbt (Dependabot added
// sbt support on 2026-05-26).
var setupActionEcosystems = []struct {
	prefix  string
	accepts []string
}{
	{"actions/setup-node", []string{"npm"}},
	{"actions/setup-go", []string{"gomod"}},
	{"actions/setup-python", []string{"pip"}},
	{"actions/setup-java", []string{"maven", "gradle", "sbt"}},
	{"ruby/setup-ruby", []string{"bundler"}},
}

// VisitStep records ecosystem requirements implied by setup actions in the workflow.
func (rule *DependabotEcosystemRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	uses := action.Uses.Value
	for _, m := range setupActionEcosystems {
		if matchesUsesPrefix(uses, m.prefix) {
			rule.setupActionReqs = append(rule.setupActionReqs, ecosystemRequirement{
				accepts: m.accepts,
				label:   m.prefix,
				pos:     action.Uses.Pos,
			})
		}
	}
	return nil
}

// matchesUsesPrefix reports whether a `uses` value refers to the given action, i.e. it is
// exactly the prefix or the prefix followed by '@' (version) or '/' (subpath). This avoids
// matching unrelated actions like "actions/setup-node-extra".
func matchesUsesPrefix(uses, prefix string) bool {
	if uses == prefix {
		return true
	}
	if strings.HasPrefix(uses, prefix) {
		return uses[len(prefix)] == '@' || uses[len(prefix)] == '/'
	}
	return false
}

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

	// Renovate is an accepted alternative to Dependabot. A broad preset enables every
	// manager, so the check is skipped entirely; otherwise only the ecosystems Renovate
	// actually manages are treated as covered (a Renovate rule scoped to npm must not
	// suppress a missing cargo warning).
	renovateManaged, renovateAll := renovateManagedEcosystems(rule.projectRoot)
	if renovateAll {
		rule.Debug("renovate broad preset manages all ecosystems, skipping dependabot-ecosystem check (path: %s)", rule.workflowPath)
		return nil
	}

	// Evaluate setup-action requirements before lockfile requirements: when the same
	// ecosystem is implied by both, dedup keeps the first occurrence, and setup-action
	// requirements carry a precise step anchor while lockfile requirements anchor at line 1.
	var reqs []ecosystemRequirement
	reqs = append(reqs, rule.setupActionReqs...)
	for _, lf := range lockfileEcosystems {
		if _, err := os.Stat(filepath.Join(rule.projectRoot, lf.file)); err == nil {
			reqs = append(reqs, ecosystemRequirement{accepts: []string{lf.ecosystem}, label: lf.file})
		}
	}
	if len(reqs) == 0 {
		return nil
	}

	// An ecosystem is covered when the dependabot config declares it or Renovate manages it.
	covered := make(map[string]bool, len(renovateManaged))
	for eco := range renovateManaged {
		covered[eco] = true
	}
	if configPath := dependabotFindConfigFile(rule.projectRoot); configPath != "" {
		eco, err := dependabotConfiguredEcosystems(configPath)
		if err != nil {
			rule.Debug("failed to parse dependabot config: %v", err)
			return nil
		}
		for e := range eco {
			covered[e] = true
		}
	}

	seen := map[string]bool{}
	for _, req := range reqs {
		if requirementSatisfied(req, covered) {
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
