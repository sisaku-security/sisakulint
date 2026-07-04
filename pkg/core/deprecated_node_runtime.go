package core

import (
	"fmt"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// DeprecatedNodeRuntimeRule detects workflows depending on deprecated
// Node.js action runtimes (node20: EOL 2026-04-30, removed from the runner
// 2026-09-16; node12/16: already removed).
//
// Detections (resolver-first: the resolved action.yml's `runs.using` is the
// ground truth):
//  1. actions declaring a deprecated runtime; auto-fix bumps well-known
//     tags to the first node24-capable major
//  2. composite actions with deprecated direct steps (depth-1, diagnose-only)
//  3. offline fallback via the embedded table when the resolver is unavailable
//  4. env vars pinning the deprecated runtime (diagnose-only)
//  5. EOL `node-version:` build targets in setup-node (diagnose-only)
//
// See https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
type DeprecatedNodeRuntimeRule struct {
	BaseRule
	metadataResolver ActionMetadataResolver
}

// First major of each well-known action that declares `runs.using: node24`;
// every lower major is deprecated, including gap majors such as
// upload-artifact v5 (v5.0.0 still declares node20). Hand-maintained,
// verified 2026-07 against each action.yml.
var nodeRuntimeFirstNode24Major = map[string]int{
	"actions/checkout":          5,
	"actions/setup-node":        5,
	"actions/setup-python":      6,
	"actions/setup-go":          6,
	"actions/github-script":     8,
	"actions/cache":             5,
	"actions/upload-artifact":   6,
	"actions/download-artifact": 7,
}

// deprecatedNodeRuntimes maps deprecated `runs.using` values to the reason
// interpolated into reports.
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

// resolveMetadata returns nil on resolution failure so callers fall back to
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

// reportDeprecatedRuntime reports the finding; auto-fix only when the table
// knows the target major and the ref is a bumpable tag.
func (rule *DeprecatedNodeRuntimeRule) reportDeprecatedRuntime(step *ast.Step, action *ast.ExecAction, using, reason string) {
	uses := action.Uses.Value
	upgradeHint := "Update the action to a version that declares node24, or contact the action maintainer."
	fixable := false
	owner, repo, ref := parseUsesValue(uses)
	if first, known := nodeRuntimeFirstNode24Major[strings.ToLower(owner+"/"+repo)]; known && ref != "" {
		actionPath := strings.TrimSuffix(uses, "@"+ref)
		upgradeHint = fmt.Sprintf("Update to %s@v%d or later, which runs on node24.", actionPath, first)
		if major, isTag := parseMajorFromRef(ref); isTag && major < first {
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

// checkCompositeTransitive reports deprecated runtimes in a composite's
// direct steps (depth-1 only). Diagnose-only: the fix belongs to the
// composite's maintainer.
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

// resolveCompositeLocalSpec turns a composite-internal "./sub" uses into
// "owner/repo/sub@ref" so it can be resolved remotely.
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
	// Reject "../.." escapes out of the parent repository.
	repoPrefix := parentParts[0] + "/" + parentParts[1]
	if joined != repoPrefix && !strings.HasPrefix(joined, repoPrefix+"/") {
		return ""
	}
	return joined + "@" + ref
}

// checkEnvFlags reports env vars pinning the deprecated runtime; GitHub env
// names are case-insensitive.
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

// parseMajorFromRef parses "v4" / "v4.1.2" tags; false for branches and SHAs.
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

// checkKnownNode20Action is the offline fallback: match `uses:` against the
// embedded table when the metadata resolver is unavailable.
func (rule *DeprecatedNodeRuntimeRule) checkKnownNode20Action(step *ast.Step, action *ast.ExecAction) {
	owner, repo, ref := parseUsesValue(action.Uses.Value)
	if owner == "" || repo == "" || ref == "" {
		return
	}
	first, known := nodeRuntimeFirstNode24Major[strings.ToLower(owner+"/"+repo)]
	if !known {
		return
	}

	major, isTag := parseMajorFromRef(ref)
	fixable := isTag
	if !isTag {
		// SHA pins carry the tag as a "# v4.1.1" comment (commit-sha auto-fix).
		comment := strings.TrimSpace(strings.TrimPrefix(action.Uses.BaseNode.LineComment, "#"))
		if m, ok := parseMajorFromRef(comment); ok {
			major = m
		} else {
			return
		}
	}

	if major >= first {
		return
	}

	actionPath := strings.TrimSuffix(action.Uses.Value, "@"+ref)
	rule.Errorf(action.Uses.Pos,
		"action '%s@%s' runs on the deprecated Node.js 20 runtime (%s). Update to %s@v%d or later, which runs on node24. See %s",
		actionPath, ref, deprecatedNodeRuntimes["node20"], actionPath, first, nodeRuntimeDocURL)
	if fixable {
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}
}

// EOL dates of Node.js majors as build targets (distinct from the action
// runtime). Source: https://github.com/nodejs/Release
var eolNodeBuildTargets = map[int]string{
	12: "2022-04-30",
	14: "2023-04-30",
	16: "2023-09-11",
	18: "2025-04-30",
	20: "2026-04-30",
}

// checkEOLNodeBuildTarget flags EOL `node-version:` in actions/setup-node.
// Diagnose-only: bumping the build target is the project owner's decision.
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
	if raw == "" || input.Value.ContainsExpression() {
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

// FixStep bumps a table-known tag to the first node24-capable major.
// SHA-pinned refs are left to the commit-sha rule.
func (rule *DeprecatedNodeRuntimeRule) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	owner, repo, ref := parseUsesValue(action.Uses.Value)
	first, known := nodeRuntimeFirstNode24Major[strings.ToLower(owner+"/"+repo)]
	if !known {
		return nil
	}
	major, isTag := parseMajorFromRef(ref)
	if !isTag || major >= first {
		return nil
	}
	// Keep subpaths: actions/cache/restore@v4 -> actions/cache/restore@v5.
	actionPath := strings.TrimSuffix(action.Uses.Value, "@"+ref)
	action.Uses.BaseNode.Value = fmt.Sprintf("%s@v%d", actionPath, first)
	return nil
}
