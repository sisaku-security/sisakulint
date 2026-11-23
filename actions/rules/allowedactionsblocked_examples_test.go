package rules

import (
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

// The examples of the false positive form actions-not-allowed are made of
// a true positive of each rule that declares the form: its workflow, with
// a job added whose step uses notAllowedAction, which the setting of
// allowed actions of the examples (actionsNotAllowedSetting) blocks.

const notAllowedAction = "example-org/not-allowed-action"

// actionsNotAllowedSetting is the setting of allowed actions that the
// examples of actions-not-allowed answer: every uses but notAllowedAction.
const actionsNotAllowedSetting = `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["*","!` + notAllowedAction + `@*"],"sha_pinning_required":false}`

// notAllowedJob is the job the examples add, at the end of the jobs.
const notAllowedJob = "  not-allowed:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + notAllowedAction + "@eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"

// lastBlockIsJobs is whether the last key of the top of text is jobs, so
// that a job written at the end of text is a job of the workflow.
func lastBlockIsJobs(text string) bool {
	last := ""
	for _, l := range strings.Split(text, "\n") {
		if l == "" || l[0] == ' ' || l[0] == '#' || !strings.Contains(l, ":") {
			continue
		}
		last = strings.Trim(strings.SplitN(l, ":", 2)[0], `"'`)
	}
	return last == "jobs" && strings.HasSuffix(text, "\n")
}

// actionsNotAllowedSource is the first true positive of m, in the order of
// its kinds that declare actions-not-allowed and of their examples, that is
// one workflow whose last top key is jobs: first one without a label
// (<kind>.yml), then any but a labeled example of an advisory (labeledAdvisory).
func actionsNotAllowedSource(m lint.Meta, kinds []lint.FindingKindID) (lint.FindingKind, lint.Example, bool) {
	for _, labeled := range []bool{false, true} {
		for _, k := range m.FindingKinds {
			if !slices.Contains(kinds, k.ID) {
				continue
			}
			plain := strings.TrimPrefix(k.ID.String(), m.ID.String()+".") + ".yml"
			for _, e := range k.TruePositives {
				if e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 || labeledAdvisory(e) || !lastBlockIsJobs(e.Text) || !labeled && path.Base(e.Name.String()) != plain {
					continue
				}
				return k, e, true
			}
		}
	}
	return lint.FindingKind{}, lint.Example{}, false
}

// actionsNotAllowedExample is the file of the example of actions-not-allowed
// of m by its path under examples/, or false when m does not declare the
// form or has no true positive to make it of.
func actionsNotAllowedExample(m lint.Meta) (string, string, bool) {
	i := slices.IndexFunc(m.FalsePositiveForms, func(f lint.FalsePositiveForm) bool { return f.ID == actionsNotAllowed })
	if i < 0 {
		return "", "", false
	}
	k, e, ok := actionsNotAllowedSource(m, m.FalsePositiveForms[i].FindingKinds)
	if !ok {
		return "", "", false
	}
	id := m.ID.String()
	n := e.Notes
	var b strings.Builder
	b.WriteString(noteLines("situation", "the workflow of the true positive "+strings.TrimPrefix(k.ID.String(), id+".")+" ("+path.Base(e.Name.String())+") of the rule, with a job added whose step uses "+notAllowedAction+", which the setting of allowed actions of GitHub (repo.allowed-actions) blocks with !"+notAllowedAction+"@*. In the true positive, "+n.Situation))
	b.WriteString(noteLines("reason", "GitHub checks each uses of the workflow before the run starts, and does not start the run because of the uses of "+notAllowedAction+": no job of the run runs, so what the reason of the true positive says does not happen (in runs that the authors of the rule made on GitHub, such runs ended as startup_failure)."))
	b.WriteString(noteLines("cause", "the rule does not read repo.allowed-actions."))
	if n.Attack != "" {
		b.WriteString(noteLines("attack", n.Attack))
	}
	if a := n.AttackValue; !a.IsZero() {
		b.WriteString("# attack-value: " + a.Carrier() + " = " + strconv.Quote(a.Value()) + "\n")
	}
	b.WriteString(noteLines("attack-run-behavior", "GitHub does not start the run, so no step of the run runs, and the attack does nothing."))
	b.WriteString(stripNotes(e.Text))
	b.WriteString(notAllowedJob)
	return path.Join("false-positive", id, actionsNotAllowed.String()+".yml"), b.String(), true
}

// stripNotes is text without the comment lines it starts with (its notes).
func stripNotes(text string) string {
	lines := strings.SplitAfter(text, "\n")
	i := 0
	for i < len(lines) && strings.HasPrefix(lines[i], "#") {
		i++
	}
	return strings.Join(lines[i:], "")
}

// TestActionsNotAllowedExamplesGenerated: the example of
// actions-not-allowed of each rule is what actionsNotAllowedExample makes
// (go test ./actions/rules -run TestActionsNotAllowedExamplesGenerated
// -update writes them), and each rule that declares the form has one.
func TestActionsNotAllowedExamplesGenerated(t *testing.T) {
	for _, m := range allMetas() {
		declares := slices.ContainsFunc(m.FalsePositiveForms, func(f lint.FalsePositiveForm) bool { return f.ID == actionsNotAllowed })
		p, want, ok := actionsNotAllowedExample(m)
		if declares && !ok {
			t.Errorf("%s declares %s but has no true positive to make its example of", m.ID, actionsNotAllowed)
			continue
		}
		if !ok {
			continue
		}
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
			t.Errorf("%s is not what actionsNotAllowedExample makes (go test ./actions/rules -run TestActionsNotAllowedExamplesGenerated -update)", full)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

// TestActionsNotAllowedKinds: each kind of the rules declares
// actions-not-allowed but runIndependentKinds, and the quality rules do
// not declare the form (their consequences are not of an attacker).
func TestActionsNotAllowedKinds(t *testing.T) {
	quality := map[lint.RuleID]bool{}
	for _, q := range Quality() {
		quality[q.QualityMeta().ID] = true
	}
	for _, m := range allMetas() {
		var declared []lint.FindingKindID
		for _, f := range m.FalsePositiveForms {
			if f.ID == actionsNotAllowed {
				declared = f.FindingKinds
			}
		}
		for _, k := range m.FindingKinds {
			want := !quality[m.ID] && !slices.Contains(runIndependentKinds, k.ID)
			if got := slices.Contains(declared, k.ID); got != want {
				t.Errorf("%s: declares %s %v, want %v", k.ID, actionsNotAllowed, got, want)
			}
		}
	}
}
