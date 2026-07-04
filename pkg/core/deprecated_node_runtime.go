package core

import (
	"fmt"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// DeprecatedNodeRuntimeRule detects GitHub Actions workflows that depend on
// the deprecated Node.js 20 action runtime (or the already-removed node12 /
// node16 runtimes). Node.js 20 reached end-of-life on 2026-04-30; GitHub
// switched the default action runtime to node24 on 2026-06-16 and will remove
// node20 from the runner on 2026-09-16.
// See https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
//
// Detections (resolver-first):
//  1. `uses:` references whose action.yml declares a deprecated runtime,
//     resolved through ActionMetadataResolver (local `./` actions offline,
//     remote actions via GitHub API). The resolved `runs.using` value is the
//     ground truth, so SHA-pinned refs are detected without relying on line
//     comments and the actual runtime (node12/16/20) is reported. Auto-fix
//     bumps well-known action tags to the first node24-capable major
//     (embedded table).
//  2. Composite actions whose direct internal steps run on a deprecated
//     runtime (depth-1, diagnose-only — the fix belongs to the action
//     maintainer, so the report points at bumping the composite itself).
//  3. Fallback when the resolver is unavailable (offline / API failure):
//     well-known action majors from the embedded table, using the tag or the
//     `# vX` line comment of SHA-pinned refs. Comments can be stale, so this
//     path is heuristic by design.
//  4. Workflow/job/step `env:` entries pinning the deprecated runtime:
//     ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION (time-limited opt-out that
//     stops working on 2026-09-16) and FORCE_JAVASCRIPT_ACTIONS_TO_NODE20
//     (removed from the runner; dead configuration). Diagnose-only.
//  5. `actions/setup-node` with an EOL `node-version:` build target
//     (Node.js <= 20). Diagnose-only because changing the build target is a
//     semantic change the project owner must decide.
type DeprecatedNodeRuntimeRule struct {
	BaseRule
	metadataResolver ActionMetadataResolver
}

// nodeRuntimeUpgrade describes, for a well-known action, the newest major
// version still running on node20 and the first major that declares node24.
type nodeRuntimeUpgrade struct {
	lastNode20Major  int
	firstNode24Major int
}

// nodeRuntimeUpgrades is an embedded snapshot (verified 2026-07 against each
// action's action.yml `runs.using` field). A production implementation should
// generate this table with a scraper, like actionlint's popular_actions DB.
var nodeRuntimeUpgrades = map[string]nodeRuntimeUpgrade{
	"actions/checkout":          {lastNode20Major: 4, firstNode24Major: 5},
	"actions/setup-node":        {lastNode20Major: 4, firstNode24Major: 5},
	"actions/setup-python":      {lastNode20Major: 5, firstNode24Major: 6},
	"actions/setup-go":          {lastNode20Major: 5, firstNode24Major: 6},
	"actions/github-script":     {lastNode20Major: 7, firstNode24Major: 8},
	"actions/cache":             {lastNode20Major: 4, firstNode24Major: 5},
	"actions/upload-artifact":   {lastNode20Major: 4, firstNode24Major: 6},
	"actions/download-artifact": {lastNode20Major: 6, firstNode24Major: 7},
}

// deprecatedNodeRuntimes are `runs.using` values that no longer receive
// security updates. node12/node16 are already removed from the runner;
// node20 is EOL and scheduled for removal on 2026-09-16.
var deprecatedNodeRuntimes = map[string]string{
	"node12": "removed from the runner",
	"node16": "removed from the runner",
	"node20": "EOL since 2026-04-30 and scheduled for removal from the runner on 2026-09-16",
}

const nodeRuntimeDocURL = "https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/"

func NewDeprecatedNodeRuntimeRule(resolver ActionMetadataResolver) *DeprecatedNodeRuntimeRule {
	return &DeprecatedNodeRuntimeRule{
		BaseRule: BaseRule{
			RuleName: "deprecated-node-runtime",
			RuleDesc: "Detects actions running on the deprecated Node.js 20 runtime (EOL 2026-04-30, removed from the runner on 2026-09-16) and workflow settings that pin the insecure runtime",
		},
		metadataResolver: resolver,
	}
}

func (rule *DeprecatedNodeRuntimeRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.checkEnvFlags(node.Env)
	return nil
}

func (rule *DeprecatedNodeRuntimeRule) VisitJobPre(node *ast.Job) error {
	rule.checkEnvFlags(node.Env)
	return nil
}

func (rule *DeprecatedNodeRuntimeRule) VisitStep(step *ast.Step) error {
	rule.checkEnvFlags(step.Env)

	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	uses := action.Uses.Value
	if strings.HasPrefix(uses, "docker://") {
		return nil
	}

	rule.checkEOLNodeBuildTarget(action)

	// Resolver-first: the action.yml at the pinned ref is the ground truth.
	// The embedded-table/comment heuristic only runs when resolution is
	// unavailable, so a stale "# v5" comment next to a node24 SHA cannot
	// produce a false positive as long as the resolver answers.
	if meta := rule.resolveMetadata(uses); meta != nil && meta.Runs != nil {
		using := strings.ToLower(meta.Runs.Using)
		if reason, deprecated := deprecatedNodeRuntimes[using]; deprecated {
			rule.reportDeprecatedRuntime(step, action, using, reason)
			return nil
		}
		if using == "composite" {
			rule.checkCompositeTransitive(action, uses, meta)
		}
		return nil
	}

	rule.checkKnownNode20Action(step, action)
	return nil
}

// resolveMetadata wraps the resolver with nil/error handling. Resolution
// failures are debug-logged and reported as nil so offline runs fall back to
// the embedded table silently.
func (rule *DeprecatedNodeRuntimeRule) resolveMetadata(spec string) *ActionMetadata {
	if rule.metadataResolver == nil {
		return nil
	}
	meta, err := rule.metadataResolver.FindMetadata(spec)
	if err != nil {
		rule.Debug("could not resolve metadata for %q: %v", spec, err)
		return nil
	}
	return meta
}

// reportDeprecatedRuntime reports a resolver-confirmed deprecated runtime and
// attaches the auto-fixer when the embedded table knows a node24-capable
// major and the ref is a bumpable tag.
func (rule *DeprecatedNodeRuntimeRule) reportDeprecatedRuntime(step *ast.Step, action *ast.ExecAction, using, reason string) {
	uses := action.Uses.Value
	upgradeHint := "Update the action to a version that declares node24, or contact the action maintainer."
	fixable := false
	owner, repo, ref := parseUsesValue(uses)
	if upgrade, known := nodeRuntimeUpgrades[strings.ToLower(owner+"/"+repo)]; known && ref != "" {
		actionPath := strings.TrimSuffix(uses, "@"+ref)
		upgradeHint = fmt.Sprintf("Update to %s@v%d or later, which runs on node24.", actionPath, upgrade.firstNode24Major)
		if major, isTag := parseMajorFromRef(ref); isTag && major <= upgrade.lastNode20Major {
			fixable = true
		}
	}
	rule.Errorf(action.Uses.Pos,
		"action '%s' runs on the deprecated Node.js runtime '%s' (%s). %s See %s",
		uses, using, reason, upgradeHint, nodeRuntimeDocURL)
	if fixable {
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}
}

// checkCompositeTransitive resolves the direct internal steps of a composite
// action and reports the ones running on a deprecated runtime. Depth-1 only:
// nested composite actions are not followed. Diagnose-only — the workflow
// author cannot rewrite a third-party composite's internals; the actionable
// remediation is bumping the composite itself.
func (rule *DeprecatedNodeRuntimeRule) checkCompositeTransitive(action *ast.ExecAction, parentSpec string, meta *ActionMetadata) {
	for _, s := range meta.Runs.Steps {
		if s == nil || s.Uses == "" {
			continue
		}
		inner := s.Uses
		if strings.HasPrefix(inner, "docker://") {
			continue
		}
		if strings.HasPrefix(inner, "./") {
			inner = resolveCompositeLocalSpec(parentSpec, inner)
			if inner == "" {
				continue
			}
		}
		im := rule.resolveMetadata(inner)
		if im == nil || im.Runs == nil {
			continue
		}
		using := strings.ToLower(im.Runs.Using)
		reason, deprecated := deprecatedNodeRuntimes[using]
		if !deprecated {
			continue
		}
		rule.Errorf(action.Uses.Pos,
			"composite action '%s' internally runs '%s' on the deprecated Node.js runtime '%s' (%s). The fix belongs to the action maintainer; check whether a newer version of the composite action resolves it. See %s",
			parentSpec, inner, using, reason, nodeRuntimeDocURL)
	}
}

// resolveCompositeLocalSpec turns a composite-internal relative uses (e.g.
// "./predicate" inside actions/attest-build-provenance@v2) into a resolvable
// remote spec ("actions/attest-build-provenance/predicate@v2").
func resolveCompositeLocalSpec(parentSpec, rel string) string {
	at := strings.LastIndex(parentSpec, "@")
	if at <= 0 || at == len(parentSpec)-1 {
		return ""
	}
	parentPath, ref := parentSpec[:at], parentSpec[at+1:]
	parentParts := strings.Split(parentPath, "/")
	if len(parentParts) < 2 {
		return ""
	}
	joined := pathpkg.Join(parentPath, rel)
	// Reject anything escaping the parent repository (e.g. "../../x").
	repoPrefix := parentParts[0] + "/" + parentParts[1]
	if joined != repoPrefix && !strings.HasPrefix(joined, repoPrefix+"/") {
		return ""
	}
	return joined + "@" + ref
}

// checkEnvFlags reports env entries that pin workflows to the deprecated
// runtime. Matching is case-insensitive because GitHub env names are.
func (rule *DeprecatedNodeRuntimeRule) checkEnvFlags(env *ast.Env) {
	if env == nil || env.Vars == nil {
		return
	}
	for _, v := range env.Vars {
		if v == nil || v.Name == nil {
			continue
		}
		switch {
		case strings.EqualFold(v.Name.Value, "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION"):
			rule.Errorf(v.Name.Pos,
				"ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION forces actions to run on the EOL Node.js 20 runtime, which no longer receives security fixes. This opt-out stops working when Node.js 20 is removed from the runner on 2026-09-16. Update the affected actions to node24-compatible versions instead. See %s",
				nodeRuntimeDocURL)
		case strings.EqualFold(v.Name.Value, "FORCE_JAVASCRIPT_ACTIONS_TO_NODE20"):
			rule.Errorf(v.Name.Pos,
				"FORCE_JAVASCRIPT_ACTIONS_TO_NODE20 was removed from the GitHub Actions runner and has no effect. Remove this dead configuration. See %s",
				nodeRuntimeDocURL)
		}
	}
}

var nodeMajorTagPattern = regexp.MustCompile(`^v(\d+)(?:\..*)?$`)

// parseMajorFromRef extracts the major version from tag-style refs such as
// "v4" or "v4.1.2". Returns false for branches, SHAs, and anything else.
func parseMajorFromRef(ref string) (int, bool) {
	m := nodeMajorTagPattern.FindStringSubmatch(ref)
	if m == nil {
		return 0, false
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return major, true
}

// checkKnownNode20Action matches `uses:` against the embedded table of
// popular actions with known node20 majors. Returns true when the action was
// conclusively identified (reported or confirmed up to date), so the caller
// can skip the metadata-resolver fallback.
func (rule *DeprecatedNodeRuntimeRule) checkKnownNode20Action(step *ast.Step, action *ast.ExecAction) bool {
	owner, repo, ref := parseUsesValue(action.Uses.Value)
	if owner == "" || repo == "" || ref == "" {
		return false
	}
	upgrade, known := nodeRuntimeUpgrades[strings.ToLower(owner+"/"+repo)]
	if !known {
		return false
	}

	major, isTag := parseMajorFromRef(ref)
	fixable := isTag
	if !isTag {
		// SHA-pinned refs carry the human-readable tag as a line comment when
		// pinned by the commit-sha auto-fix (e.g. "# v4.1.1").
		comment := strings.TrimSpace(strings.TrimPrefix(action.Uses.BaseNode.LineComment, "#"))
		comment = strings.TrimSpace(comment)
		if m, ok := parseMajorFromRef(comment); ok {
			major = m
		} else {
			return false
		}
	}

	if major > upgrade.lastNode20Major {
		return true // already on a node24-capable major
	}

	actionPath := strings.TrimSuffix(action.Uses.Value, "@"+ref)
	rule.Errorf(action.Uses.Pos,
		"action '%s@%s' runs on the deprecated Node.js 20 runtime (%s). Update to %s@v%d or later, which runs on node24. See %s",
		actionPath, ref, deprecatedNodeRuntimes["node20"], actionPath, upgrade.firstNode24Major, nodeRuntimeDocURL)
	if fixable {
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}
	return true
}

// eolNodeBuildTargets are Node.js majors that are EOL as build targets
// (distinct from the action runtime): 16 (2023-09-11), 18 (2025-04-30),
// 20 (2026-04-30). Source: https://github.com/nodejs/Release
var eolNodeBuildTargets = map[int]string{
	12: "2022-04-30",
	14: "2023-04-30",
	16: "2023-09-11",
	18: "2025-04-30",
	20: "2026-04-30",
}

// checkEOLNodeBuildTarget warns when actions/setup-node installs an EOL
// Node.js as the build/test runtime. Diagnose-only: bumping the project's
// Node target is a semantic change (package compatibility, engines field)
// that the maintainer must drive, typically via Renovate/Dependabot.
func (rule *DeprecatedNodeRuntimeRule) checkEOLNodeBuildTarget(action *ast.ExecAction) {
	owner, repo, _ := parseUsesValue(action.Uses.Value)
	if !strings.EqualFold(owner, "actions") || !strings.EqualFold(repo, "setup-node") {
		return
	}
	input, ok := action.Inputs["node-version"]
	if !ok || input == nil || input.Value == nil {
		return
	}
	raw := strings.TrimSpace(input.Value.Value)
	if raw == "" || strings.Contains(raw, "${{") {
		return
	}
	majorPart := strings.SplitN(strings.TrimPrefix(raw, "v"), ".", 2)[0]
	major, err := strconv.Atoi(majorPart)
	if err != nil {
		return
	}
	if eolDate, isEOL := eolNodeBuildTargets[major]; isEOL {
		rule.Errorf(input.Value.Pos,
			"Node.js %s specified in 'node-version' reached end-of-life on %s and no longer receives security updates. Migrate the project to a supported Node.js version (>= 22). See https://github.com/nodejs/Release",
			raw, eolDate)
	}
}

// FixStep bumps a known node20-generation action tag to the first
// node24-capable major (e.g. actions/checkout@v4 -> @v5). SHA-pinned refs are
// left to the commit-sha rule to re-pin after the bump.
func (rule *DeprecatedNodeRuntimeRule) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	owner, repo, ref := parseUsesValue(action.Uses.Value)
	upgrade, known := nodeRuntimeUpgrades[strings.ToLower(owner+"/"+repo)]
	if !known {
		return nil
	}
	major, isTag := parseMajorFromRef(ref)
	if !isTag || major > upgrade.lastNode20Major {
		return nil
	}
	// Preserve any subpath (e.g. actions/cache/restore@v4 must stay
	// actions/cache/restore@v5, not become actions/cache@v5).
	actionPath := strings.TrimSuffix(action.Uses.Value, "@"+ref)
	action.Uses.BaseNode.Value = fmt.Sprintf("%s@v%d", actionPath, upgrade.firstNode24Major)
	return nil
}
