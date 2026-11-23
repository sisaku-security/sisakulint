package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// splitRepo is the repository the split examples put the called workflow
// in, and remoteCommit the commit its answer is at.
const (
	splitRepo       = "example-org/wf"
	splitCalledPath = ".github/workflows/w.yml"
)

// splitExample is the workflow text of an example split in two: called,
// the workflow with on: workflow_call in place of its on, and callerHead,
// the on and the permissions of the example, which a caller calls called
// with. ok is false when the example is not one workflow with on and jobs,
// or is called already.
func splitExample(text string) (called, callerHead string, ok bool) {
	blocks := topBlocks(text)
	on, hasOn := blocks["on"]
	if _, hasJobs := blocks["jobs"]; !hasOn || !hasJobs || strings.Contains(text, "workflow_call") {
		return "", "", false
	}
	called = strings.Replace(text, on, "on: workflow_call\n", 1)
	callerHead = on
	if p, ok := blocks["permissions"]; ok {
		callerHead += p
	}
	return called, callerHead, true
}

// topBlocks are the blocks of the top-level keys of text: each key's line
// and the lines after it up to the next line that starts with a key.
func topBlocks(text string) map[string]string {
	out := map[string]string{}
	lines := strings.SplitAfter(text, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if l == "" || l[0] == ' ' || l[0] == '#' || l[0] == '\n' || !strings.Contains(l, ":") {
			continue
		}
		key := strings.Trim(strings.SplitN(l, ":", 2)[0], `"'`)
		b := l
		for i+1 < len(lines) && (lines[i+1] == "\n" || strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "#")) {
			i++
			b += lines[i]
		}
		out[key] = b
	}
	return out
}

// withWorkflow answers workflow.definition of splitCalledPath of splitRepo
// with content, and the rest from below: another path of splitRepo, such as
// a reusable workflow that the called workflow calls in turn, is not among
// the files of the same repository's form either.
type withWorkflow struct {
	below   facts.Resolver
	content string
}

func (w withWorkflow) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if d, ok := q.(facts.WorkflowDefinition); ok && d.Repo.String() == splitRepo && d.Path.String() == splitCalledPath {
		sha, _ := facts.ParseSHA(strings.Repeat("e", 40))
		b, err := json.Marshal(facts.WorkflowFile{Commit: sha, Content: w.content})
		if err != nil {
			panic(err)
		}
		return facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceFile}
	}
	return w.below.Resolve(ctx, q)
}

// splitKinds are the kinds of what the rule of newReg reports in the
// called workflow of files, with the facts of e and the answer of the
// called workflow; the findings of the caller itself (its own secrets:
// inherit, say) differ by where the called workflow is, and are left out.
func splitKinds(t *testing.T, newReg func() (*lint.Registry, error), files map[string]string, e lint.Example, called string) ([]string, lint.Report) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	b, err := facts.EncodeFile(e.Facts)
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newReg()
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, withWorkflow{store, called})
	for _, x := range rep.Errors {
		t.Errorf("internal error: %+v", x)
	}
	// what is in the called workflow: at it, or moved from it to the uses
	// of the caller (the first Evidence in the value of the fact)
	inCalled := func(d lint.FindingDraft) bool {
		return d.Location.File.Input.String() == splitCalledPath || len(d.Evidence) > 0 && d.Evidence[0].Location.File.Query != nil
	}
	var kinds []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if inCalled(f.FindingDraft) {
			kinds = append(kinds, f.Args.KindID().String())
		}
	}
	for _, f := range rep.QualityFindings {
		if inCalled(f.FindingDraft) {
			kinds = append(kinds, f.Args.KindID().String())
		}
	}
	slices.Sort(kinds)
	return kinds, rep
}

// remoteDiffers are the kinds that a rule does not report in a reusable
// workflow of another repository, by the rule, with the undetected form
// that declares so: GitHub's pin of such a step was not tried.
var remoteDiffers = map[string]struct{ kind, form string }{
	"allowed-actions": {"allowed-actions.unpinned-action", "remote-called-pinning"},
}

// TestRemoteCalledMatchesLocal: each true positive of a workflow, split in
// a caller and a called workflow, gets the same findings when the called
// workflow is of another repository (workflow.definition answers it) as
// when it is of the same repository; those of the other repository are at
// the uses of the caller.
func TestRemoteCalledMatchesLocal(t *testing.T) {
	type rq struct {
		m   lint.Meta
		reg func() (*lint.Registry, error)
	}
	var all []rq
	for _, r := range All() {
		all = append(all, rq{exampledMeta(r), func() (*lint.Registry, error) { return lint.NewRegistry([]lint.Rule{r}) }})
	}
	for _, q := range Quality() {
		all = append(all, rq{q.(lint.ExampledQualityRule).ExampledQualityMeta().AsMeta(), func() (*lint.Registry, error) { return lint.NewRegistry(nil, q) }})
	}
	checked := 0
	for _, x := range all {
		m := x.m
		if !slices.ContainsFunc(m.UndetectedForms, func(f lint.UndetectedForm) bool { return f.ID == lint.RemoteCalleeForm.ID }) {
			continue // a rule that does not read reusable workflows of other repositories
		}
		for _, k := range m.FindingKinds {
			for _, e := range k.TruePositives {
				if e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 {
					continue
				}
				called, head, ok := splitExample(e.Text)
				if !ok {
					continue
				}
				local, _ := splitKinds(t, x.reg, map[string]string{
					".github/workflows/c.yml": head + "jobs:\n  c:\n    uses: ./" + splitCalledPath + "\n    secrets: inherit\n",
					splitCalledPath:           called,
				}, e, called)
				if len(local) == 0 {
					continue
				}
				remote, rep := splitKinds(t, x.reg, map[string]string{
					".github/workflows/c.yml": head + "jobs:\n  c:\n    uses: " + splitRepo + "/" + splitCalledPath + "@" + strings.Repeat("e", 40) + "\n    secrets: inherit\n",
				}, e, called)
				checked++
				// a kind that the rule does not report in a reusable workflow
				// of another repository, as an undetected form declares
				if f, ok := remoteDiffers[m.ID.String()]; ok {
					if !slices.ContainsFunc(m.UndetectedForms, func(u lint.UndetectedForm) bool {
						return u.ID.String() == f.form && slices.Contains(u.FindingKinds, lint.MustFindingKindID(f.kind))
					}) {
						t.Errorf("%s does not declare %s for %s", m.ID, f.form, f.kind)
					}
					local = slices.DeleteFunc(local, func(k string) bool { return k == f.kind })
					if slices.Contains(remote, f.kind) {
						t.Errorf("%s %s: the other repository's form reports %s, which %s declares not reported", m.ID, e.Name, f.kind, f.form)
					}
				}
				if !slices.Equal(local, remote) {
					t.Errorf("%s %s: the other repository's form reports %v, the same repository's %v", m.ID, e.Name, remote, local)
					continue
				}
				for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
					if f.Location.File.Input.String() != ".github/workflows/c.yml" {
						t.Errorf("%s %s: a finding at %v", m.ID, e.Name, f.Location.File)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal(fmt.Sprint("no example checked"))
	}
}
