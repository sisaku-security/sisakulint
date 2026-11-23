package rules

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// The examples of lint.RemoteCalleeForm and lint.RemoteCalleeUnknownKind,
// and a true positive of the same form with an answer, are made of a true
// positive of each rule (remoteSource): its workflow is the reusable
// workflow of another repository that a job calls (splitExample). Each
// repository of these says which answer workflow.definition has
// (workflowDefinitionAnswer): <rule>-remote the reusable workflow,
// <rule>-unanswered none, <rule>-unknown unknown.
const remoteCalleeLabel = "remote-callee"

// remoteSource is the first true positive of m, in the order of its kinds
// and of their examples, that splitExample splits; ok is false when none
// is.
func remoteSource(m lint.Meta) (k lint.FindingKind, e lint.Example, called, head string, ok bool) {
	for _, k := range m.FindingKinds {
		for _, e := range k.TruePositives {
			// the true positive on status, check_suite or check_run
			// (<kind>.status-commit.yml) shows the runs of an outside app,
			// and a labeled true positive of an advisory (labeledAdvisory)
			// the form of the advisory, not the form of the kind, which the
			// others show; a true positive of an added attacker gives no
			// finding in the run that adds no attacker, which checks the
			// examples made of the source
			if e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 || labeledAdvisory(e) || len(e.Notes.AddedAttackers) != 0 || strings.HasSuffix(e.Name.String(), "."+remoteCalleeLabel+".yml") || strings.HasSuffix(e.Name.String(), ".status-commit.yml") {
				continue
			}
			if called, head, ok := splitExample(e.Text); ok {
				return k, e, called, head, true
			}
		}
	}
	return lint.FindingKind{}, lint.Example{}, "", "", false
}

// remoteRepoOf is the repository the examples of rule put the reusable
// workflow in, for the answer of workflow.definition named by suffix.
func remoteRepoOf(rule lint.RuleID, suffix string) string {
	return "example-org/" + rule.String() + "-" + suffix
}

// remoteSourceOf is the reusable workflow of the examples of
// remoteRepoOf(rule, "remote"), found by the name of the repository.
func remoteSourceOf(repo string) (string, bool) {
	name, ok := strings.CutPrefix(repo, "example-org/")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(name, "-remote")
	if !ok {
		return "", false
	}
	for _, m := range allMetas() {
		if m.ID.String() == id {
			_, _, called, _, ok := remoteSource(m)
			return called, ok
		}
	}
	return "", false
}

// noteLines writes the note key with text, wrapped as the examples are:
// lines of up to 76 bytes, the rest indented by two spaces.
func noteLines(key, text string) string {
	var b strings.Builder
	line, words := "# "+key+":", 0
	for _, w := range strings.Fields(text) {
		if words > 0 && len(line)+1+len(w) > 76 {
			b.WriteString(line + "\n")
			line, words = "#  ", 0
		}
		line += " " + w
		words++
	}
	b.WriteString(line + "\n")
	return b.String()
}

// attackNotes are the notes of the attack of n.
func attackNotes(n lint.ExampleNotes) string {
	var b strings.Builder
	if n.Attack != "" {
		b.WriteString(noteLines("attack", n.Attack))
	}
	if a := n.AttackValue; !a.IsZero() {
		b.WriteString("# attack-value: " + a.Carrier() + " = " + strconv.Quote(a.Value()) + "\n")
	}
	if n.AttackRunBehavior != "" {
		b.WriteString(noteLines("attack-run-behavior", n.AttackRunBehavior))
	}
	return b.String()
}

// remoteCalleeExamples are the files of the remote examples of m, by their
// path under examples/.
func remoteCalleeExamples(m lint.Meta, quality bool) map[string]string {
	if !targetsWorkflows(m) || !slices.ContainsFunc(m.UndetectedForms, func(f lint.UndetectedForm) bool { return f.ID == lint.RemoteCalleeForm.ID }) {
		return nil
	}
	out := map[string]string{}
	id := m.ID.String()
	k, e, _, head, ok := remoteSource(m)
	// the caller of the true positive passes the secrets, which the
	// reusable workflow may read; the callers of the others have no
	// finding of their own (a full SHA, no permissions, no secrets)
	caller := func(suffix string) string {
		return head + "jobs:\n  c:\n    uses: " + remoteRepoOf(m.ID, suffix) + "/.github/workflows/w.yml@v1\n    secrets: inherit\n"
	}
	quiet := func(suffix string) string {
		return topBlocks(head)["on"] + "permissions: {}\njobs:\n  c:\n    uses: " + remoteRepoOf(m.ID, suffix) + "/.github/workflows/w.yml@" + strings.Repeat("e", 40) + "\n"
	}
	source := ""
	attack := ""
	if ok {
		source = "the workflow of the true positive " + strings.TrimPrefix(k.ID.String(), id+".") + " (" + path.Base(e.Name.String()) + ") of the rule, with on: workflow_call in place of the on of " + path.Base(e.Name.String())
		attack = attackNotes(e.Notes)
	} else {
		head = "on: pull_request_target\n"
		source = "a workflow"
		if !quality {
			attack = noteLines("attack", "the attacker opens a pull request from a fork, which runs the jobs of the reusable workflow on pull_request_target") +
				noteLines("attack-run-behavior", "the jobs of the reusable workflow run on pull_request_target, the event that started the run of the calling job")
		}
	}
	if quality {
		attack = ""
	}
	out[path.Join("undetected", id, remoteCalleeLabel+".yml")] = noteLines("situation", "a job calls the reusable workflow .github/workflows/w.yml of the repository "+remoteRepoOf(m.ID, "unanswered")+", whose content is "+source+". The linter has no answer of the fact workflow.definition for the reusable workflow.") +
		noteLines("reason", "a todo (a fact): the jobs of a reusable workflow run on the event that started the run of the calling job, and the linter does not read the reusable workflow.") +
		noteLines("cause", "the rule reads a reusable workflow of another repository only from the answer of workflow.definition.") +
		attack + quiet("unanswered")
	if !quality {
		out[path.Join("inconclusive", id, lint.RemoteCalleeUnknownKind.ID.String()+".yml")] = noteLines("situation", "a job calls the reusable workflow .github/workflows/w.yml of the repository "+remoteRepoOf(m.ID, "unknown")+", whose content is "+source+". The linter asked the fact workflow.definition for the reusable workflow and got no answer.") +
			noteLines("reason", "what the jobs of the reusable workflow do is in the file that the linter could not read; whoever changes the uses, such as the author of a pull request, can name a reusable workflow that the token that the linter uses cannot read.") +
			attack + quiet("unknown")
	}
	if ok {
		p := path.Join("true-positive", id, strings.TrimPrefix(k.ID.String(), id+".")+"."+remoteCalleeLabel+".yml")
		if _, err := os.Stat(path.Join("examples", p)); err == nil && !isGenerated(path.Join("examples", p)) {
			return out // a true positive of the label written by hand
		}
		out[p] = noteLines("situation", "a job calls the reusable workflow .github/workflows/w.yml of the repository "+remoteRepoOf(m.ID, "remote")+", which the fact workflow.definition answers with "+source+". The job passes its secrets with secrets: inherit. In the true positive, "+e.Notes.Situation) +
			noteLines("reason", "the jobs of a reusable workflow run on the event that started the run of the calling job, so the reason of the true positive holds: "+e.Notes.Reason) +
			attack + caller("remote")
	}
	return out
}

// remoteGeneratedMark is the line each generated true positive starts
// with (the start of its situation), which tells it
// from one written by hand.
const remoteGeneratedMark = "# situation: a job calls the reusable workflow .github/workflows/w.yml of\n"

// isGenerated is whether the file at p is a generated true positive.
func isGenerated(p string) bool {
	b, err := os.ReadFile(p)
	return err == nil && bytes.HasPrefix(b, []byte(remoteGeneratedMark))
}

// targetsWorkflows is whether m reads workflows.
func targetsWorkflows(m lint.Meta) bool {
	for _, t := range m.Targets {
		if t == lint.InputKindWorkflow {
			return true
		}
	}
	return false
}

// TestRemoteCalleeExamplesGenerated: the remote examples of each rule are
// what remoteCalleeExamples makes (go test ./actions/rules -run
// TestRemoteCalleeExamplesGenerated -update writes them).
func TestRemoteCalleeExamplesGenerated(t *testing.T) {
	quality := map[lint.RuleID]bool{}
	for _, q := range Quality() {
		quality[q.QualityMeta().ID] = true
	}
	for _, m := range allMetas() {
		for p, want := range remoteCalleeExamples(m, quality[m.ID]) {
			full := path.Join("examples", p)
			if *update {
				if err := os.MkdirAll(path.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			got, err := os.ReadFile(full)
			if errors.Is(err, fs.ErrNotExist) || err == nil && string(got) != want {
				t.Errorf("%s is not what remoteCalleeExamples makes (go test ./actions/rules -run TestRemoteCalleeExamplesGenerated -update)", full)
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}

// notReadingRemote are the rules that read workflows but not the reusable
// workflows of other repositories (lint.RuleContext.RemoteCalled): the
// update tool of the repository does not update another repository.
var notReadingRemote = []lint.RuleID{DependabotGitHubActionsID}

// TestRemoteCalleeDeclared: each rule that reads workflows declares
// lint.RemoteCalleeForm, and each that is not a quality rule also
// lint.RemoteCalleeUnknownKind, but those of notReadingRemote.
func TestRemoteCalleeDeclared(t *testing.T) {
	quality := map[lint.RuleID]bool{}
	for _, q := range Quality() {
		quality[q.QualityMeta().ID] = true
	}
	for _, m := range allMetas() {
		if !targetsWorkflows(m) || slices.Contains(notReadingRemote, m.ID) {
			continue
		}
		if !slices.ContainsFunc(m.UndetectedForms, func(f lint.UndetectedForm) bool { return f.ID == lint.RemoteCalleeForm.ID }) {
			t.Errorf("%s does not declare the undetected form %s", m.ID, lint.RemoteCalleeForm.ID)
		}
		if !quality[m.ID] && !slices.ContainsFunc(m.InconclusiveKinds, func(k lint.InconclusiveKind) bool { return k.ID == lint.RemoteCalleeUnknownKind.ID }) {
			t.Errorf("%s does not declare the inconclusive kind %s", m.ID, lint.RemoteCalleeUnknownKind.ID)
		}
	}
}

// labeledAdvisory is whether e, an example of one file, is a labeled
// example (<kind>.<label>) whose notes cite an advisory: it keeps the form
// of the advisory. A main example (<kind>) that cites one is the form of
// its kind too. An example of several files, whose main file has the name
// of its place in the repository, is never one; the callers leave those
// out first.
func labeledAdvisory(e lint.Example) bool {
	id, _ := strings.CutSuffix(path.Base(e.Name.String()), ".yml")
	id, _ = strings.CutSuffix(id, ".action")
	return len(e.Notes.Advisories) != 0 && strings.Contains(id, ".")
}
