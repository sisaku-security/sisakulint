package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// CalledContextRead is a read of the secrets context that names no secret
// (SecretsContextRead) in Node, a reusable workflow that a job calls or
// one that it calls in turn: one that makes the calling job read every
// secret.
type CalledContextRead struct {
	Node calls.Node
	Read SecretsContextRead
}

// calledReader reads what a job reads of the secrets through the
// reusable workflows it calls, those of the call graph g whose contents
// the linter has (calledNodes). GitHub passes the runner of a called job
// the secrets that the job reads of what its caller passes: with secrets:
// inherit, those the job reads by name, and every secret when it reads the
// secrets context without a name; by name, the keys the job reads. The
// runs that showed so called a reusable workflow by ./ and by
// owner/repo/path@sha, of the same repository and of another repository
// of the same organization, and two calls deep.
type calledReader struct {
	g     *calls.Graph
	stack map[calls.Node]bool // the workflows being read: a call back to one is a loop, which GitHub refuses
	memo  map[calls.Node]calledResult
	loops *int // how many calls back to a workflow being read were met: a result that met none is kept
}

// calledResult is what the jobs of a workflow read.
type calledResult struct {
	secrets Secrets
	reads   []CalledContextRead
}

// newCalledReader reads in g for the jobs of the node self, which is on
// the stack from the start: a call back to it is a loop.
func newCalledReader(g *calls.Graph, self calls.Node) calledReader {
	r := calledReader{g: g, stack: map[calls.Node]bool{}, memo: map[calls.Node]calledResult{}, loops: new(int)}
	if !self.IsZero() {
		r.stack[self] = true
	}
	return r
}

// job is what the job j of w, the workflow of the node n, reads, and the
// reads of the secrets context without a name that make it read every
// secret: of the values of j when in (j is a job of a called workflow),
// and those of the workflows it calls. n is zero when there is no graph.
func (r calledReader) job(n calls.Node, w *workflow.Workflow, j workflow.Job, in bool) (Secrets, []CalledContextRead) {
	var s Secrets
	var reads []CalledContextRead
	seen := map[string]bool{}
	read := func(v workflow.String) {
		s.read(v, seen)
		if in {
			for _, c := range SecretsContextReadsIn(v) {
				reads = append(reads, CalledContextRead{Node: n, Read: c})
			}
		}
	}
	if j.Kind != workflow.JobCall {
		for _, v := range MapValues(w.Env) { // not passed to a called workflow (reusing-workflow-configurations)
			read(v)
		}
	}
	for _, v := range jobValuesOf(j, false) {
		read(v)
	}
	if j.Kind != workflow.JobCall {
		return s, reads
	}
	nodes := r.calledNodes(n, j)
	if len(nodes) == 0 { // the linter does not have the contents of the called workflow
		s.All = s.All || j.InheritSecrets
		for _, v := range MapValues(j.Secrets) {
			read(v)
		}
		return s, reads
	}
	called, calledReads := r.workflows(nodes)
	switch {
	case j.InheritSecrets:
		s.add(called, seen)
		reads = append(reads, calledReads...)
	case j.Secrets.Status == workflow.Present:
		for _, e := range j.Secrets.Value.Entries {
			if e.Value.Status == workflow.Present && (called.All || called.reads(e.Key.AsString())) {
				read(e.Value.Value)
			}
		}
	default: // a ${{ }} of the whole map, or none
		for _, v := range MapValues(j.Secrets) {
			read(v)
		}
	}
	return s, dedupReads(reads)
}

// calledNodes are the reusable workflows the job j of the node self calls
// whose contents the linter has: those of the inputs (./ and $/), and the
// remote called workflows that the fact workflow.definition answered.
func (r calledReader) calledNodes(self calls.Node, j workflow.Job) []calls.Node {
	if r.g == nil || self.IsZero() {
		return nil
	}
	var out []calls.Node
	for _, c := range r.g.CalledBy(self) {
		if c.Job == nil || c.StepIndex >= 0 || !c.Resolved || c.Job.ID.AsString() != j.ID.AsString() {
			continue
		}
		_, input := c.Called.Input()
		_, remote := c.Called.Remote()
		if input || remote {
			out = append(out, c.Called)
		}
	}
	return out
}

// workflows is what the jobs of the workflows of nodes read, together.
func (r calledReader) workflows(nodes []calls.Node) (Secrets, []CalledContextRead) {
	var s Secrets
	var reads []CalledContextRead
	seen := map[string]bool{}
	for _, n := range nodes {
		ws, wr := r.workflow(n)
		s.add(ws, seen)
		reads = append(reads, wr...)
	}
	return s, reads
}

// workflow is what the jobs of the workflow of n read, together; nothing
// for a workflow being read, which a loop calls back (GitHub refuses a loop
// of calls and runs none of it).
func (r calledReader) workflow(n calls.Node) (Secrets, []CalledContextRead) {
	if r.stack[n] {
		*r.loops++
		return Secrets{}, nil
	}
	if m, ok := r.memo[n]; ok {
		return m.secrets, m.reads
	}
	before := *r.loops
	f, ok := r.g.File(n)
	if !ok || f.Workflow == nil || f.Workflow.Jobs.Status != workflow.Present {
		return Secrets{All: true}, nil
	}
	r.stack[n] = true
	defer delete(r.stack, n)
	var s Secrets
	var reads []CalledContextRead
	seen := map[string]bool{}
	for _, je := range f.Workflow.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present || JobReach(f.Workflow, &je.Value.Value).AlwaysSkipped() {
			continue // GitHub skips such a job in every run: its runner gets no secret
		}
		js, jr := r.job(n, f.Workflow, je.Value.Value, true)
		s.add(js, seen)
		reads = append(reads, jr...)
	}
	if *r.loops == before {
		r.memo[n] = calledResult{s, reads}
	}
	return s, reads
}

// add adds to s what o reads, but its token: the token of a called job is
// not the calling job's.
func (s *Secrets) add(o Secrets, seen map[string]bool) {
	s.All = s.All || o.All
	for _, name := range o.Names {
		if f := expr.FoldName(name); !seen[f] {
			seen[f] = true
			s.Names = append(s.Names, name)
		}
	}
}

// reads is whether s reads the secret name by its name.
func (s Secrets) reads(name string) bool {
	return slices.ContainsFunc(s.Names, func(n string) bool { return expr.FoldName(n) == expr.FoldName(name) })
}

// dedupReads is rs with each ${{ }} once, in the order of rs: a workflow
// that two calls reach (B and C each call D) is read twice.
func dedupReads(rs []CalledContextRead) []CalledContextRead {
	type key struct {
		node        calls.Node
		start, part int
	}
	seen := map[key]bool{}
	var out []CalledContextRead
	for _, r := range rs {
		k := key{r.Node, r.Read.Value.Node.ContentSpan().Start, r.Read.Part}
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}
