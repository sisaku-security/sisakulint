package composite

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// MaxCallDepth is how deep ExpandCall reads the reusable workflows of
// other repositories: the workflow a job calls is at depth 1 (the default
// of the upstream's -D).
const MaxCallDepth = 3

// Called is a reusable workflow of another repository read: the uses from
// the job to it (Chain, its own last, with the commit of the answer), its
// workflow (nil when the file is not one) and what the model rejects of
// it, the value of the fact it is read from, the job that calls it (the job ExpandCall reads, or a job of
// the workflow at Parent), and the index of that workflow in
// CallExpansion.Workflows (-1 for the job ExpandCall reads).
type Called struct {
	Chain       []Hop
	Workflow    *workflow.Workflow
	Diagnostics []workflow.Diagnostic
	Origin      Origin
	By          *workflow.Job
	Parent      int
}

// CallExpansion is what ExpandCall reads of a job: the workflows, in the
// order read (depth first, in the order of the jobs), and the calls not
// answered.
type CallExpansion struct {
	Workflows  []Called
	Unanswered []Unanswered
}

// parsedWorkflow is the answer of a workflow.definition, read once.
type parsedWorkflow struct {
	once   sync.Once
	answer facts.RawAnswer
	file   facts.WorkflowFile
	tree   *cst.Tree
	wf     *workflow.Workflow
	diags  []workflow.Diagnostic
	err    bool // the value does not fit WorkflowFile
}

// ExpandCall reads the reusable workflow of another repository the job j
// calls (workflow.definition), and those its jobs call, to MaxCallDepth.
// A call of the inputs (./ and $/ of a workflow of the run) is not read
// here: the run reads it. In a workflow read, ./ and $/ name a workflow of
// the same commit of its repository: "When you reference a reusable
// workflow in the same repository using $/ or ./ (without {owner}/{repo}
// and @{ref}), the called workflow is from the same commit as the caller
// workflow."
// (https://github.com/github/docs/blob/6cbe6413ac7177bb692a78c171a74ae8be50d721/data/reusables/actions/reusable-workflow-calling-syntax.md?plain=1#L7)
// Each repository, path and commit is read once for each job that calls it.
func (x *Reader) ExpandCall(ctx context.Context, j *workflow.Job) CallExpansion {
	var out CallExpansion
	if j.Kind != workflow.JobCall || j.Uses.Status != workflow.Present {
		return out
	}
	u := j.Uses.Value
	kind := u.Kind
	if kind == workflow.UsesFolded {
		kind = u.Folded
	}
	if kind != workflow.UsesRemote {
		return out
	}
	seen := map[string]bool{}
	for _, run := range u.Actions() {
		if q, ok := workflowOf(run.Owner+"/"+run.Repo, run.Path.String(), run.Ref); ok {
			x.call(ctx, &out, seen, q, u.AsString(), nil, j, -1)
		}
	}
	return out
}

// call reads the workflow q, called by uses text after chain from the job
// by of the workflow at parent (-1: the job ExpandCall reads), and what its
// jobs call.
func (x *Reader) call(ctx context.Context, out *CallExpansion, seen map[string]bool, q facts.WorkflowDefinition, text string, chain []Hop, by *workflow.Job, parent int) {
	if len(chain) >= MaxCallDepth {
		// a workflow the linter does not read: as one asked with no answer
		out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: true, Deep: true, Reason: "deeper than the 3 levels of reusable workflows the linter reads"})
		return
	}
	p := x.workflowAnswer(ctx, q)
	switch {
	case p.err:
		out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: true, Reason: "the value of " + q.Kind().String() + " is not a workflow file"})
		return
	case p.answer.State == facts.StateAbsent:
		return // no workflow there: GitHub does not start the run
	case p.answer.State != facts.StateFound:
		out.Unanswered = append(out.Unanswered, Unanswered{Chain: hops(chain, Hop{Uses: text}), Asked: p.answer.Source != facts.SourceUnset, Reason: p.answer.Reason})
		return
	}
	// once for each workflow and the job that calls it: two jobs that call
	// one workflow give it different with and secrets
	key := strings.ToLower(q.Repo.String()) + "/" + q.Path.String() + "@" + p.file.Commit.String() + " " + strconv.Itoa(parent) + " " + by.ID.AsString()
	if seen[key] {
		return
	}
	seen[key] = true
	c := Called{Chain: hops(chain, Hop{Uses: text, Commit: p.file.Commit}), Workflow: p.wf, Diagnostics: p.diags, Origin: Origin{Query: q, Tree: p.tree}, By: by, Parent: parent}
	at := len(out.Workflows)
	out.Workflows = append(out.Workflows, c)
	if p.wf == nil {
		return
	}
	for i := range p.wf.Jobs.Value.Entries {
		j := &p.wf.Jobs.Value.Entries[i].Value.Value
		if j.Kind != workflow.JobCall || j.Uses.Status != workflow.Present {
			continue
		}
		u := j.Uses.Value
		kind := u.Kind
		if kind == workflow.UsesFolded {
			kind = u.Folded
		}
		switch kind {
		case workflow.UsesRemote:
			for _, run := range u.Actions() {
				if next, ok := workflowOf(run.Owner+"/"+run.Repo, run.Path.String(), run.Ref); ok {
					x.call(ctx, out, seen, next, u.AsString(), c.Chain, j, at)
				}
			}
		case workflow.UsesLocal, workflow.UsesSelf:
			// the same commit of the called workflow's repository
			rest := strings.TrimPrefix(strings.TrimPrefix(u.Path.Text, "./"), "$/")
			if next, ok := workflowOf(q.Repo.String(), rest, p.file.Commit.String()); ok {
				x.call(ctx, out, seen, next, u.AsString(), c.Chain, j, at)
			}
		}
	}
}

// workflowAnswer is the answer of q, asked and parsed once for the Reader.
func (x *Reader) workflowAnswer(ctx context.Context, q facts.WorkflowDefinition) *parsedWorkflow {
	x.mu.Lock()
	p, ok := x.workflows[q]
	if !ok {
		p = &parsedWorkflow{}
		x.workflows[q] = p
	}
	x.mu.Unlock()
	p.once.Do(func() {
		p.answer = facts.Checked(q, x.r.Resolve(ctx, q))
		if p.answer.State != facts.StateFound {
			return
		}
		if err := json.Unmarshal(p.answer.Value, &p.file); err != nil {
			p.err = true
			return
		}
		p.tree = cst.Parse([]byte(p.file.Content))
		p.wf, p.diags = workflow.Parse(p.tree)
	})
	return p
}

// workflowOf is the workflow.definition of the workflow at path of repo,
// at ref.
func workflowOf(repo, path, ref string) (facts.WorkflowDefinition, bool) {
	r, err := facts.ParseRepo(repo)
	if err != nil || ref == "" {
		return facts.WorkflowDefinition{}, false
	}
	p, err := facts.ParseUsesPath(path)
	if err != nil {
		return facts.WorkflowDefinition{}, false
	}
	return facts.WorkflowDefinition{Repo: r, Path: p, Ref: ref}, true
}
