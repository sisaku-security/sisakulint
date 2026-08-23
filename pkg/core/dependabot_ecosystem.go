package core

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// dependabotEcosystemReported deduplicates project-level (root-lockfile) warnings across
// workflow files in a single Lint run. LintFiles constructs a fresh DependabotEcosystemRule
// per workflow, so without this guard the same missing-root-lockfile warning would repeat
// at line 1 of every workflow file in the repo. The key is the project root joined with
// the lockfile label and the ecosystem signature, so distinct lockfiles in the same repo
// still surface independently. Setup-action requirements are anchored to a step position
// and are not deduplicated through this map — they are inherently per-workflow.
//
// Concurrency: this is a process-wide global, reset at the start of each public Lint
// entrypoint via resetDependabotEcosystemRunState. Individual sync.Map ops are atomic,
// but the dedupe semantics break under concurrent Lint() / LintFile() / LintFiles()
// calls from the same process — a reset from one in-flight run can clear entries that
// another in-flight run depends on, re-emitting the same project-level warning. CLI
// usage is single-threaded and unaffected; library users that need per-run isolation
// must serialize their Lint calls (or wrap them in their own mutex).
var dependabotEcosystemReported sync.Map

// resetDependabotEcosystemRunState clears the cross-workflow dedupe map. The Linter calls
// this at the start of each public Lint / LintFiles entry so that library users running
// multiple Lint passes in one process keep seeing warnings, and tests can isolate runs.
func resetDependabotEcosystemRunState() {
	dependabotEcosystemReported.Range(func(key, _ any) bool {
		dependabotEcosystemReported.Delete(key)
		return true
	})
}

// DependabotEcosystemRule detects package ecosystems (npm/gomod/pip/cargo/bundler/composer/
// maven/gradle) inferred from root-level lockfiles and workflow setup actions that are
// missing from the dependabot configuration. The github-actions ecosystem is intentionally
// out of scope (handled by DependabotGitHubActionsRule). Local-scan only; diagnose-only.
type DependabotEcosystemRule struct {
	BaseRule
	workflowPath string
	isRemote     bool
	projectRoot  string
	// reportProjectFindings is false for context-only workflows in a
	// pull-request scan. Those workflows must not consume the run-wide dedupe
	// key for root-lockfile findings that should be anchored to a target file.
	reportProjectFindings bool
	// setupActionReqs collects ecosystem requirements derived from setup actions in the
	// current workflow, anchored to the step position for precise reporting.
	setupActionReqs []ecosystemRequirement
	// runCommands collects the raw shell text of `run:` steps in the current workflow. It
	// corroborates setup-action ecosystem requirements: a setup-* action that only bootstraps
	// the runtime to run stdlib-only scripts does not manage dependencies and must not imply a
	// dependabot ecosystem.
	runCommands []string
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
		workflowPath:          workflowPath,
		isRemote:              isRemote,
		reportProjectFindings: true,
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
	rule.runCommands = nil
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

// VisitStep records ecosystem requirements implied by setup actions in the workflow, and
// collects `run:` step shell text used to corroborate those requirements.
func (rule *DependabotEcosystemRule) VisitStep(step *ast.Step) error {
	if run, ok := step.Exec.(*ast.ExecRun); ok {
		if run.Run != nil && run.Run.Value != "" {
			rule.runCommands = append(rule.runCommands, run.Run.Value)
		}
		return nil
	}
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

// setupActionCorroborationFiles maps a dependabot ecosystem to root-level manifest/lockfile
// patterns that corroborate a setup-action requirement. Entries may contain '*' globs (e.g.
// requirements*.txt). A setup-* action is frequently used merely to run stdlib-only scripts; the
// requirement is only reported when one of these files exists at the repository root or a `run`
// step invokes the ecosystem's package manager.
var setupActionCorroborationFiles = map[string][]string{
	"npm":      {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "package.json"},
	"gomod":    {"go.sum", "go.mod"},
	"cargo":    {"Cargo.lock", "Cargo.toml"},
	"bundler":  {"Gemfile.lock", "Gemfile"},
	"composer": {"composer.lock", "composer.json"},
	"pip":      {"Pipfile.lock", "poetry.lock", "uv.lock", "requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile"},
	"maven":    {"pom.xml"},
	"gradle":   {"build.gradle", "build.gradle.kts", "gradle.lockfile"},
	"sbt":      {"build.sbt"},
}

// packageManagerCommandPatterns maps ecosystems to shell patterns of their package manager being
// invoked in a `run` step. A match corroborates a setup-action requirement for that ecosystem.
var packageManagerCommandPatterns = []struct {
	ecosystems []string
	re         *regexp.Regexp
}{
	{[]string{"npm"}, regexp.MustCompile(`(?i)\b(npm|npx|yarn|pnpm|bun|corepack)\b`)},
	{[]string{"gomod"}, regexp.MustCompile(`(?i)\bgo (mod|get|install|run|build|test|vet)\b`)},
	{[]string{"pip"}, regexp.MustCompile(`(?i)\b(pip|pip3|pipx|pipenv|poetry|conda|uv|pdm)\b`)},
	{[]string{"maven", "gradle", "sbt"}, regexp.MustCompile(`(?i)\b(mvn|mvnw|gradle|gradlew|sbt)\b`)},
	{[]string{"bundler"}, regexp.MustCompile(`(?i)\bbundle (install|exec|add|update|check)\b`)},
}

// setupActionCorroborated reports whether the setup-action requirement is backed by evidence that
// the ecosystem's package manager is actually used: a recognized root-level manifest/lockfile for
// one of the accepted ecosystems, or a `run` step invoking that ecosystem's package manager.
func (rule *DependabotEcosystemRule) setupActionCorroborated(req ecosystemRequirement) bool {
	for _, eco := range req.accepts {
		if rule.rootHasEcosystemFile(eco) || rule.runUsesEcosystemManager(eco) {
			return true
		}
	}
	return false
}

// rootHasEcosystemFile reports whether the repository root contains a manifest/lockfile pattern
// associated with the ecosystem. Patterns may contain '*' globs (e.g. requirements*.txt).
func (rule *DependabotEcosystemRule) rootHasEcosystemFile(ecosystem string) bool {
	for _, pattern := range setupActionCorroborationFiles[ecosystem] {
		full := filepath.Join(rule.projectRoot, pattern)
		if strings.Contains(pattern, "*") {
			if matches, err := filepath.Glob(full); err == nil && len(matches) > 0 {
				return true
			}
			continue
		}
		if _, err := os.Stat(full); err == nil {
			return true
		}
	}
	return false
}

// runUsesEcosystemManager reports whether any `run` step in the current workflow invokes a
// package manager of the ecosystem.
func (rule *DependabotEcosystemRule) runUsesEcosystemManager(ecosystem string) bool {
	if len(rule.runCommands) == 0 {
		return false
	}
	for _, m := range packageManagerCommandPatterns {
		if !slices.Contains(m.ecosystems, ecosystem) {
			continue
		}
		for _, cmd := range rule.runCommands {
			if m.re.MatchString(cmd) {
				return true
			}
		}
	}
	return false
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

	// A setup-* action alone does not prove the ecosystem's package manager is used — the
	// runtime may serve only to run stdlib-only scripts, in which case dependabot would have no
	// manifest to update. Report the setup-action requirement only when it is corroborated by a
	// root manifest/lockfile for an accepted ecosystem or by a `run` step invoking that
	// ecosystem's package manager. Lockfile signals (below) are unaffected.
	rule.setupActionReqs = slices.DeleteFunc(rule.setupActionReqs, func(req ecosystemRequirement) bool {
		return !rule.setupActionCorroborated(req)
	})

	// Evaluate setup-action requirements before lockfile requirements: when the same
	// ecosystem is implied by both, dedup keeps the first occurrence, and setup-action
	// requirements carry a precise step anchor while lockfile requirements anchor at line 1.
	reqs := slices.Clone(rule.setupActionReqs)
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

		// Project-level findings (pos == nil) come from root lockfiles, which are a
		// repository attribute, not a per-workflow one. Report each (projectRoot,
		// lockfile, ecosystem) combination at most once per Lint run so a repo with N
		// workflow files does not emit the same line-1 warning N times. Setup-action
		// findings carry a step anchor and stay per-workflow.
		if req.pos == nil {
			if !rule.reportProjectFindings {
				continue
			}
			repoKey := rule.projectRoot + "\x00" + req.label + "\x00" + key
			if _, loaded := dependabotEcosystemReported.LoadOrStore(repoKey, struct{}{}); loaded {
				continue
			}
		}

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
