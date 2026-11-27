package rules

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestRemoteCompositeUses: archived-uses and known-vulnerable-actions read
// the uses inside a composite action of another repository that
// action.definition answers: the finding is at the uses of the workflow,
// and the evidence in the file of the fact. The finding of
// known-vulnerable-actions has no fix (the repository does not write the
// composite action), so its workflow is not a true positive of a kind
// that fixes.
func TestRemoteCompositeUses(t *testing.T) {
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, c := range []struct {
		file string
		want string
	}{
		{"examples/true-positive/archived-uses/archived-repository.remote-composite.yml", "archived-uses.archived-repository actions/create-release@v1"},
		{"testdata/remotecomposite/known-vulnerable.yml", "known-vulnerable-actions.advisory-high actions/download-artifact@eaceaf801fd36c7dee90939fad912460b18a1ffe"},
	} {
		fsys := fstest.MapFS{".github/workflows/w.yml": {Data: read(c.file)}}
		var got []string
		add := func(fs []lint.FindingDraft) {
			for _, f := range fs {
				inFact := slices.ContainsFunc(f.Evidence, func(e lint.Related) bool { return e.Location.File.Query != nil })
				if inFact && strings.Contains(f.Detected(), strings.Fields(c.want)[1]) {
					got = append(got, f.Args.KindID().String()+" "+strings.Fields(c.want)[1])
				}
			}
		}
		if strings.Contains(c.file, "archived-uses") {
			for _, f := range qualityReportFS(t, ArchivedUsesID, fsys, limitFacts{}).QualityFindings {
				add([]lint.FindingDraft{f.FindingDraft})
			}
		} else {
			rep, _, _ := checkRules(t, []lint.Rule{KnownVulnerableActions}, map[string]string{".github/workflows/w.yml": string(read(c.file))}, limitFacts{})
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				add([]lint.FindingDraft{f.FindingDraft})
			}
		}
		if !slices.Contains(got, c.want) {
			t.Errorf("%s: %v, want %s with the evidence in the file of the fact", c.file, got, c.want)
		}
	}
}

// TestRemoteCalledCacheMode: cache-poisoning reads the cache-mode of the
// jobs of a reusable workflow of another repository that
// workflow.definition answers, when the calling job writes none: the
// finding writable-job is at the uses of the calling job, with the
// evidence in the file of the fact, and has no fix (cache-mode read or
// none in the caller would stop the called workflow from starting), so
// its workflow is not a true positive of a kind that fixes.
func TestRemoteCalledCacheMode(t *testing.T) {
	b, err := os.ReadFile("testdata/remotecall/writable-job.yml")
	if err != nil {
		t.Fatal(err)
	}
	rep, _, _ := checkRules(t, []lint.Rule{CachePoisoning}, map[string]string{".github/workflows/w.yml": string(b)}, limitFacts{})
	found := false
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Args.KindID() != kindCachePoisoningWritableJob {
			continue
		}
		inFact := slices.ContainsFunc(f.Evidence, func(e lint.Related) bool { return e.Location.File.Query != nil })
		if inFact && f.Fix == nil && f.NoFix != nil && f.Location.File.Query == nil {
			found = true
		}
	}
	if !found {
		t.Errorf("findings %+v, want writable-job at the uses with the evidence in the file of the fact and no fix", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestRemoteCalledArchivedUses: archived-uses reads the uses inside a
// reusable workflow of another repository that workflow.definition
// answers: a step of its job (the evidence in the file of the fact), and a
// job of it that calls another reusable workflow (the hops in the anchor),
// at the uses of the calling job. The examples hold with repo.archived the
// other way too, so they do not tell these findings from that of the
// calling uses.
func TestRemoteCalledArchivedUses(t *testing.T) {
	for _, c := range []struct {
		file, uses string
		inFact     bool
	}{
		{"examples/true-positive/archived-uses/archived-repository.remote-called.yml", "actions/create-release@v1", true},
		{"examples/true-positive/archived-uses/archived-repository.remote-called-call.yml", "actions/create-release/.github/workflows/release.yml@v1", true},
	} {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		fsys := fstest.MapFS{".github/workflows/w.yml": {Data: b}}
		found := false
		for _, f := range qualityReportFS(t, ArchivedUsesID, fsys, limitFacts{}).QualityFindings {
			inFact := slices.ContainsFunc(f.Evidence, func(e lint.Related) bool { return e.Location.File.Query != nil })
			if strings.Contains(f.Detected(), c.uses) && inFact == c.inFact && f.Location.File.Query == nil {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no finding of %s at the uses of the calling job (evidence in the fact: %v)", c.file, c.uses, c.inFact)
		}
	}
}

// TestRemoteDuplicates: findings of places of other repositories that a
// step or a job runs, all at the uses of the step or the job, are told
// apart by the path of each place in its file: two jobs of a called
// workflow with the same uses, two steps with the same name in a composite
// action, two agent steps with the same prompt, and two steps that use one
// composite action whose step runs an agent give a finding each and no
// error.
func TestRemoteDuplicates(t *testing.T) {
	const pr = "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.issue.number }}/head\n      - uses: example-org/two-save-composite@v1\n"
	for _, c := range []struct {
		name     string
		rule     lint.Rule
		quality  lint.RuleID
		workflow string
		kind     string
	}{
		{"two jobs, archived-uses", nil, ArchivedUsesID, "on: push\njobs:\n  call:\n    uses: example-org/two-jobs-workflow/.github/workflows/w.yml@v1\n", "archived-uses.archived-repository"},
		{"two jobs, deprecated-node-runtime", nil, DeprecatedNodeRuntimeID, "on: push\njobs:\n  call:\n    uses: example-org/two-jobs-workflow/.github/workflows/w.yml@v1\n", "deprecated-node-runtime.used-action"},
		{"two saves, cache-poisoning", CachePoisoning, lint.RuleID{}, pr, "cache-poisoning.saved-checkout"},
		{"two agents, prompt-injection", AIActionPromptInjection, lint.RuleID{}, "on:\n  issues:\n    types: [opened, labeled]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/two-agent-composite@v1\n", "ai-action-prompt-injection.prompt"},
		{"one agent composite in two steps, prompt-injection", AIActionPromptInjection, lint.RuleID{}, "on:\n  issues:\n    types: [opened, labeled]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/claude-prompt-composite@v1\n      - uses: example-org/claude-prompt-composite@v1\n", "ai-action-prompt-injection.prompt"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var kinds []string
			var errs []lint.RunError
			if c.rule == nil {
				rep := qualityReportFS(t, c.quality, fstest.MapFS{".github/workflows/w.yml": {Data: []byte(c.workflow)}}, limitFacts{})
				errs = rep.Errors
				for _, f := range rep.QualityFindings {
					kinds = append(kinds, f.Args.KindID().String())
				}
			} else {
				rep, _, _ := checkRules(t, []lint.Rule{c.rule}, map[string]string{".github/workflows/w.yml": c.workflow}, limitFacts{})
				errs = rep.Errors
				for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
					kinds = append(kinds, f.Args.KindID().String())
				}
			}
			if len(errs) != 0 {
				t.Fatalf("errors %+v", errs)
			}
			n := 0
			for _, k := range kinds {
				if k == c.kind {
					n++
				}
			}
			if n < 2 {
				t.Errorf("%d findings of %s, want one for each place: %v", n, c.kind, kinds)
			}
		})
	}
}

// TestRemoteIfsBetween: a cache step of a composite action that a step of
// a composite action of another repository runs past an if of push only
// does not run on issue_comment: no saved-checkout there.
func TestRemoteIfsBetween(t *testing.T) {
	const w = "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.issue.number }}/head\n      - uses: example-org/guarded-outer-composite@v1\n"
	rep, _, _ := checkRules(t, []lint.Rule{CachePoisoning}, map[string]string{".github/workflows/w.yml": w}, limitFacts{})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Args.KindID() == kindCachePoisoningSavedCheckout {
			t.Errorf("saved-checkout %+v, though the step that runs the cache step runs on push only", f)
		}
	}
}

// TestRemoteUnknownAIOnPush: an action of another repository with no
// answer that a step of a push job uses gives no remote-unknown of the AI
// rules: no attacker's text reaches an agent there.
func TestRemoteUnknownAIOnPush(t *testing.T) {
	const w = "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/unreachable-composite@v1\n"
	for _, r := range []lint.Rule{AIActionPromptInjection, AIActionExcessiveTools, AIActionUnrestrictedTrigger, AIActionUnsafeSandbox, AIActionExecutionOrder} {
		rep, _, _ := checkRules(t, []lint.Rule{r}, map[string]string{".github/workflows/w.yml": w}, askedFacts{})
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			if g.InconclusiveKind == remoteUnknown {
				t.Errorf("%s: remote-unknown on a push job: %+v", r.Meta().ID, g)
			}
		}
	}
	// the same action on an issue of an attacker gives it
	const issues = "on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/unreachable-composite@v1\n"
	rep, _, _ := checkRules(t, []lint.Rule{AIActionPromptInjection}, map[string]string{".github/workflows/w.yml": issues}, askedFacts{})
	if !slices.ContainsFunc(rep.FindingsWith(lint.CertaintyInconclusive), func(g lint.Finding) bool { return g.InconclusiveKind == remoteUnknown }) {
		t.Errorf("no remote-unknown on issues: %+v", rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestRemoteUnknownAIOnStatus: on status alone, the AI rules that do not
// read the runs of an outside app (app-commit-event) give no remote-unknown
// for an action of another repository with no answer; ai-action-unsafe-sandbox,
// which reads those runs, gives it.
func TestRemoteUnknownAIOnStatus(t *testing.T) {
	const w = "on: status\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/unreachable-composite@v1\n"
	for _, r := range []lint.Rule{AIActionPromptInjection, AIActionExcessiveTools, AIActionUnrestrictedTrigger, AIActionExecutionOrder} {
		rep, _, _ := checkRules(t, []lint.Rule{r}, map[string]string{".github/workflows/w.yml": w}, askedFacts{})
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			if g.InconclusiveKind == remoteUnknown {
				t.Errorf("%s: remote-unknown on a status job: %+v", r.Meta().ID, g)
			}
		}
	}
	rep, _, _ := checkRules(t, []lint.Rule{AIActionUnsafeSandbox}, map[string]string{".github/workflows/w.yml": w}, askedFacts{})
	if !slices.ContainsFunc(rep.FindingsWith(lint.CertaintyInconclusive), func(g lint.Finding) bool { return g.InconclusiveKind == remoteUnknown }) {
		t.Errorf("ai-action-unsafe-sandbox: no remote-unknown on status: %+v", rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// askedFacts is limitFacts whose unknown answers of action.definition come
// from GitHub, as in a run with --online: asked, with no answer.
type askedFacts struct{}

func (askedFacts) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	a := limitFacts{}.Resolve(ctx, q)
	if _, ok := q.(facts.ActionDefinition); ok && a.State == facts.StateUnknown {
		a.Source = facts.SourceGitHub
	}
	return a
}
