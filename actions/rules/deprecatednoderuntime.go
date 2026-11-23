package rules

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// DeprecatedNodeRuntime is the quality rule deprecated-node-runtime: an
// action that declares runs.using node12, node16 or node20, which the
// runner runs on Node.js 24; a setting
// of env that GitHub's runners do not obey; and a node-version of
// actions/setup-node whose support ended. The runs.using of an
// action of another repository is the fact action.runs-using; that of an
// action.yml of the inputs is read where it is written, and not again at
// each uses: ./ of it.
var DeprecatedNodeRuntime lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.DeprecatedNodeRuntimeReader](deprecatedNodeRuntime{}, ir.DeprecatedNodeRuntimeView))

// DeprecatedNodeRuntimeID is the ID of deprecated-node-runtime.
var DeprecatedNodeRuntimeID = lint.MustRuleID("deprecated-node-runtime")

type deprecatedNodeRuntime struct{}

func (deprecatedNodeRuntime) QualityMeta() lint.QualityMeta { return deprecatedNodeRuntimeMeta }

// deprecatedRunsUsing are the values of runs.using older than node24.
var deprecatedRunsUsing = []facts.RunsUsing{facts.RunsUsingNode12, facts.RunsUsingNode16, facts.RunsUsingNode20}

func (deprecatedNodeRuntime) Check(ctx context.Context, c *lint.RuleContext, v ir.DeprecatedNodeRuntimeReader) error {
	for _, s := range v.RunsUsingSites() {
		if u, err := facts.ParseRunsUsing(strings.ToLower(s.Using())); err == nil && slices.Contains(deprecatedRunsUsing, u) {
			c.Report(lint.FindingDraft{Location: c.At(s.At()), Args: DeprecatedNodeRuntimeDeclaredRuntime{RunsUsing: s.Using()}})
		}
	}
	for _, u := range v.Uses() {
		if u.Level() != ir.UsesInStep || u.Outside() {
			continue // a reusable workflow has no runs.using; owner/repo does not run when the path goes outside it
		}
		f, ok, err := usedAction(ctx, c, u.Repo(), u.Path(), u.Ref(), u.UsesText())
		if err != nil {
			return err
		}
		if ok {
			f.Location = c.At(u.RefAt())
			c.Report(f)
		}
	}
	// the uses inside the composite actions of other repositories that the
	// steps run (action.definition); those of an action.yml of the inputs
	// are the findings of that input
	for _, call := range v.CompositeCalls() {
		for _, s := range call.Steps() {
			if s.Query == nil || s.Repo == "" {
				continue
			}
			f, ok, err := usedAction(ctx, c, s.Repo, s.Path, s.Ref, s.UsesText)
			if err != nil {
				return err
			}
			if ok {
				f.Location, f.Anchor = c.At(call.At()), placeAnchor(c, s.Chain, s.At)
				f.Evidence = []lint.Related{{Location: c.At(s.At), Note: "the step of the composite action " + s.Chain[len(s.Chain)-1].Uses + " that uses the action"}}
				c.Report(f)
			}
		}
	}
	// the reusable workflows of other repositories the jobs call
	// (workflow.definition) are read where the engine runs the rule on them
	// (a remote called workflow), and reported at the uses of the calling job
	for _, s := range v.NodeRuntimeSettings() {
		c.Report(lint.FindingDraft{Location: c.At(s.At()), Args: DeprecatedNodeRuntimeRuntimeSetting{Name: s.Name()}})
	}
	for _, s := range v.SetupNodeVersions() {
		major, ok := nodeMajor(s.NodeVersion())
		if !ok {
			continue
		}
		if end, ok := nodeEndOfLife[major]; ok {
			c.Report(lint.FindingDraft{Location: c.At(s.At()), Args: DeprecatedNodeRuntimeEolNodeVersion{NodeVersion: s.NodeVersion(), Major: major, EndOfLife: end.String()}})
		}
	}
	return nil
}

// usedAction is the finding of the action repo/path@ref, written uses,
// when the action declares, or may declare, an older runs.using than
// node24 (action.runs-using); false when it does not, or is not an action.
func usedAction(ctx context.Context, c *lint.RuleContext, repoText, pathText, ref, uses string) (lint.FindingDraft, bool, error) {
	repo, err := facts.ParseRepo(repoText)
	if err != nil {
		return lint.FindingDraft{}, false, nil
	}
	var path facts.UsesPath
	if pathText != "" {
		if path, err = facts.ParseUsesPath(pathText); err != nil {
			return lint.FindingDraft{}, false, nil // not a path a fact asks about (white space, a backslash)
		}
	}
	q := facts.ActionRunsUsing{Repo: repo, Path: path, Ref: ref}
	var leaves []lint.Condition
	for _, d := range deprecatedRunsUsing {
		leaf, err := lint.FactEq(q, d)
		if err != nil {
			return lint.FindingDraft{}, false, err
		}
		leaves = append(leaves, leaf)
	}
	cond := lint.Any(leaves...)
	// the value the action declares, for the text, when the fact has an
	// answer; the condition decides whether the finding holds
	declared := "node12, node16 or node20"
	if a := q.Ask(ctx, c.Resolver); a.State == facts.StateFound {
		if !slices.Contains(deprecatedRunsUsing, a.Value) {
			return lint.FindingDraft{}, false, nil
		}
		declared = a.Value.String()
	} else if a.State == facts.StateAbsent {
		return lint.FindingDraft{}, false, nil
	}
	return lint.FindingDraft{Args: DeprecatedNodeRuntimeUsedAction{Uses: uses, RunsUsing: declared}, Condition: &cond}, true, nil
}

// nodeMajor is the major version node-version names when it is a version
// (18, v18, 18.x, 18.2.0): the number before the first dot, after an
// optional v, written without leading zeros; of a version before 4 (0.12,
// 0.10.48), 0 and the number after it, as nodejs/Release names those. A
// range, an alias (lts/hydrogen), a build that is not a release
// (16-nightly) or a file is not read.
func nodeMajor(v string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	number := func(s string) (string, bool) {
		n, err := strconv.Atoi(s)
		if s == "" || strings.Trim(s, "0123456789") != "" || err != nil {
			return "", false
		}
		return strconv.Itoa(n), true
	}
	major, ok := number(parts[0])
	if !ok || major != "0" {
		return major, ok
	}
	if len(parts) < 2 {
		return "", false
	}
	minor, ok := number(parts[1])
	return "0." + minor, ok
}

// nodeEndOfLife are the major versions of Node.js whose support had ended
// on 2026-10-20, as nodeMajor names them, and the day each ended: every
// end of schedule.json of nodejs/Release at
// 72fdab20216c5f04e0a0fe72a225c2504e9f2b42 on or before that day. A major
// that reaches its end later is not here (UndetectedForm
// later-eol).
var nodeEndOfLife = map[string]lint.Date{
	"0.8": lint.MustDate("2014-07-31"), "0.10": lint.MustDate("2016-10-31"), "0.12": lint.MustDate("2016-12-31"),
	"4": lint.MustDate("2018-04-30"), "5": lint.MustDate("2016-06-30"), "6": lint.MustDate("2019-04-30"), "7": lint.MustDate("2017-06-30"),
	"8": lint.MustDate("2019-12-31"), "9": lint.MustDate("2018-06-30"), "10": lint.MustDate("2021-04-30"), "11": lint.MustDate("2019-06-01"),
	"12": lint.MustDate("2022-04-30"), "13": lint.MustDate("2020-06-01"), "14": lint.MustDate("2023-04-30"), "15": lint.MustDate("2021-06-01"),
	"16": lint.MustDate("2023-09-11"), "17": lint.MustDate("2022-06-01"), "18": lint.MustDate("2025-04-30"), "19": lint.MustDate("2023-06-01"),
	"20": lint.MustDate("2026-04-30"), "21": lint.MustDate("2024-06-01"), "23": lint.MustDate("2025-06-01"), "25": lint.MustDate("2026-06-01"),
}

// runnerSource is the version of actions/runner that the rule was checked
// against.
const runnerSource = "https://github.com/actions/runner/blob/v2.338.0/"

var deprecatedNodeRuntimeMeta = lint.QualityMeta{
	ID:       DeprecatedNodeRuntimeID,
	Problem:  "an action.yml of the repository, or an action of another repository that a step uses, declares an older Node.js version than node24; an env sets a setting of the Node.js version of actions; or actions/setup-node sets up a Node.js version whose support ended",
	Expected: "every JavaScript action (an action whose runs.using names a Node.js version) declares runs.using: node24 or later; no env sets ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION or FORCE_JAVASCRIPT_ACTIONS_TO_NODE20; and the node-version of actions/setup-node names a Node.js version that is still supported",
	Citations: []lint.Citation{
		lint.MustCitation(runnerSource + "src/Runner.Worker/Handlers/HandlerFactory.cs"),
		lint.MustCitation(runnerSource + "src/Runner.Common/Util/NodeUtil.cs"),
		lint.MustCitation(runnerSource + "src/Runner.Worker/ActionManifestManager.cs"),
		lint.MustCitation("https://github.com/github/docs/blob/666463860bec200da6c8db9cb9334e7335d9b753/content/actions/reference/workflows-and-actions/metadata-syntax.md"),
		lint.MustCitation("https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/"),
		lint.MustCitation("https://github.com/nodejs/Release/blob/72fdab20216c5f04e0a0fe72a225c2504e9f2b42/schedule.json"),
		lint.MustCitation("https://github.com/actions/setup-node/blob/949feb2413d6458794dcd2491c4babbbce0c15c1/README.md"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textDeprecatedNodeRuntimeDeclaredRuntime},
		{FindingText: textDeprecatedNodeRuntimeEolNodeVersion},
		{FindingText: textDeprecatedNodeRuntimeRuntimeSetting},
		{FindingText: textDeprecatedNodeRuntimeUsedAction, FactKinds: []facts.Kind{facts.KindActionRunsUsing}},
	},
	// Offline, every step's uses of another repository would be
	// conditional: the rule runs by default only where an answer of
	// action.runs-using can come, the kinds that need no fact too.
	DefaultRun: lint.DefaultRunFacts(facts.KindActionRunsUsing),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: remoteComposite, Text: "a uses inside the action.yml of a composite action of another repository (a step of that composite action, not the uses that names the composite action) when action.definition has no answer for the composite action (a run without --online and without the answer in --facts, an answer of unknown, or an action deeper than the 4 levels of actions the linter reads): the rule reads the steps of a composite action of another repository only from the answer", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("outside-other-path"), Text: "a uses whose path goes with .. above the root of its repository into the directory where the runner puts another uses' action, and names an action at another path there: the rule reads the other uses, not the action at that path", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("node-version-alias"), Text: "a node-version of actions/setup-node that is an alias (lts/hydrogen), a range (>=18) or a build that is not a release (16-nightly, canary), which may resolve to a version whose support ended: the version is chosen when the workflow runs, and the rule reads only a version (18, v18, 18.x)", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("node-version-expression"), Text: "a node-version of actions/setup-node written as a ${{ }}, such as a variable of a matrix: the rule reads only a version written as it is", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("node-version-file"), Text: "a node-version-file of actions/setup-node, such as .nvmrc: the rule does not read the file", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("github-env"), Text: "a setting of the Node.js version of actions written to $GITHUB_ENV by a step (echo ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true >> $GITHUB_ENV): the rule reads the keys of env only", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("later-eol"), Text: "a node-version of a major version of Node.js whose support ends after the table of the rule was written (2026-10-20): after the end of the support (Node.js 22: 2027-04-30), the rule does not report the node-version, since the table has only the major versions whose support had ended on 2026-10-20", Disposition: lint.Todo(lint.NeedFact)},
	}),
}
