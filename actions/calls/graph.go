package calls

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// File is an input of a run, as the graph reads it.
type File struct {
	Name     facts.InputPath
	Tree     *cst.Tree
	Workflow *workflow.Workflow       // when it is a workflow
	Action   *workflow.ActionMetadata // when it is an action.yml
	Remote   *RemoteCalled            // when it is a remote called workflow, not an input (Name is zero)
}

// Node is the node of f in a graph.
func (f File) Node() Node {
	if f.Remote != nil {
		return RemoteNode(f.Remote)
	}
	return InputNode(f.Name)
}

// Call is a job or a step of Caller that calls a workflow or an action of
// the inputs, or a job that calls a remote called workflow.
type Call struct {
	Caller    Node
	Job       *workflow.Job  // nil for a step of a composite action
	StepIndex int            // the step's workflow.Step.Order; -1 for a job that calls a workflow
	Step      *workflow.Step // nil for a job that calls a workflow
	With      workflow.Field[workflow.Map[workflow.String]]
	// Resolved is whether the file the call runs is the input it names:
	// a step's ./path runs what the workspace has, which is the input only
	// after a checkout of the repository at the run's commit into its root.
	Resolved bool
}

// Graph is the calls among the inputs of a run.
type Graph struct {
	files    []File
	byName   map[Node]int
	calls    map[Node][]Call // by called
	complete bool
	missing  bool
	remotes  []*RemoteCalled
}

// New is the graph of files. complete is whether they are the whole
// repository, missing whether some files of it are not among them: a path
// left out, or a file not read. repo is the repository they are of, or the
// zero Repo when it is not known: a uses: owner/repo/path@ref that names it
// runs another version of the input at path, a caller that is not
// resolved (when repo is not known, any owner/repo with a path that is an
// input).
func New(files []File, complete, missing bool, repo facts.Repo) *Graph {
	g := &Graph{files: files, byName: map[Node]int{}, calls: map[Node][]Call{}, complete: complete, missing: missing}
	for i, f := range files {
		g.byName[f.Node()] = i
	}
	for _, f := range files {
		for _, c := range callsIn(f) {
			if !ownTarget(c, repo) {
				continue // another repository's; or, not knowing the repository, any action at the root of one
			}
			if called, ok := g.called(c.target); ok && g.callable(c.Call, called) {
				g.calls[called] = append(g.calls[called], c.Call)
			}
		}
	}
	for _, cs := range g.calls {
		slices.SortStableFunc(cs, func(a, b Call) int { return CompareNodes(a.Caller, b.Caller) })
	}
	return g
}

// File is the file of the node name.
func (g *Graph) File(name Node) (File, bool) {
	i, ok := g.byName[name]
	if !ok {
		return File{}, false
	}
	return g.files[i], true
}

// CallsOf are the calls of called, by the caller (CompareNodes), each
// caller's in the order written: one for a remote called workflow.
func (g *Graph) CallsOf(called Node) []Call {
	return g.calls[called]
}

// CalledCall is a call and the input it calls.
type CalledCall struct {
	Call
	Called Node
}

// CalledBy are the calls caller makes of the inputs and of remote called
// workflows, in the order caller writes them.
func (g *Graph) CalledBy(caller Node) []CalledCall {
	var out []CalledCall
	for called, cs := range g.calls {
		for _, c := range cs {
			if c.Caller == caller {
				out = append(out, CalledCall{Call: c, Called: called})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b CalledCall) int {
		if d := callOffset(a.Call) - callOffset(b.Call); d != 0 {
			return d
		}
		return CompareNodes(a.Called, b.Called)
	})
	return out
}

// callOffset is where c is written in its caller.
func callOffset(c Call) int {
	if c.Step != nil {
		return c.Step.Node.ContentSpan().Start
	}
	return c.Job.Node.ContentSpan().Start
}

// Coverage is how much of the callers of called the inputs have: all, for
// a remote called workflow, which is read for its one caller.
func (g *Graph) Coverage(called Node) analysis.CallerCoverage {
	cs := g.calls[called]
	if len(cs) == 0 {
		return analysis.CallerCoverageNone
	}
	if _, ok := called.Remote(); ok {
		return analysis.CallerCoverageAll // its one caller, the chain it is read for
	}
	f, _ := g.File(called)
	// a step anywhere may call an action, also from a file left out or not
	// read; a workflow is called by jobs of .github/workflows, which is
	// never left out (a workflow not read there is GitHub's to refuse)
	if !g.complete || f.Action != nil && g.missing || slices.ContainsFunc(cs, func(c Call) bool { return !c.Resolved }) {
		return analysis.CallerCoveragePartial
	}
	return analysis.CallerCoverageAll
}

// Dependents are the nodes name calls, and those they call (CompareNodes),
// each once: those whose callers it is among.
func (g *Graph) Dependents(name Node) []Node {
	seen := map[Node]bool{name: true}
	var out []Node
	var visit func(Node)
	visit = func(n Node) {
		for called, cs := range g.calls {
			if seen[called] || !slices.ContainsFunc(cs, func(c Call) bool { return c.Caller == n }) {
				continue
			}
			seen[called] = true
			out = append(out, called)
			visit(called)
		}
	}
	visit(name)
	slices.SortFunc(out, CompareNodes)
	return out
}

// callable is whether GitHub runs called for c: a job calls a workflow
// that can be called (workflow_call), a step an action.
func (g *Graph) callable(c Call, called Node) bool {
	f, _ := g.File(called)
	if c.StepIndex >= 0 {
		return f.Action != nil
	}
	if w := f.Workflow; w != nil && w.On.Status == workflow.Present {
		_, ok := w.On.Value.Event(workflow.EventNameWorkflowCall)
		return ok
	}
	return false
}

// called is the input target names: the file itself, or action.yml or
// action.yaml in the directory; "" is the root.
func (g *Graph) called(target string) (Node, bool) {
	for _, n := range TargetPaths(target) {
		if _, ok := g.byName[InputNode(n)]; ok {
			return InputNode(n), true
		}
	}
	return Node{}, false
}

// Targets are the paths the calls of f name in its own repository (repo,
// as New reads it): the file itself, or the directory of an action.yml or
// action.yaml; "" is the root. They may name an input that is not among
// the files of a graph, such as one not read.
func Targets(f File, repo facts.Repo) []string {
	var out []string
	for _, c := range callsIn(f) {
		if ownTarget(c, repo) {
			out = append(out, c.target)
		}
	}
	return out
}

// TargetPaths are the inputs target may name: the file itself, or
// action.yml or action.yaml in the directory; "" is the root.
func TargetPaths(target string) []facts.InputPath {
	paths := []string{target, target + "/action.yml", target + "/action.yaml"}
	if target == "" {
		paths = []string{"action.yml", "action.yaml"}
	}
	var out []facts.InputPath
	for _, p := range paths {
		if n, err := facts.CleanInputPath(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ownTarget is whether c names a path of repo: ./ and $/, or
// owner/repo/path@ref of repo; with repo not known, any owner/repo with a
// path.
func ownTarget(c found, repo facts.Repo) bool {
	return c.repo == "" || !repo.IsZero() && strings.EqualFold(c.repo, repo.String()) || repo.IsZero() && c.target != ""
}

// AddRemote adds r to g, called by the one call by: the job before it in
// its chain, of an input or of the remote called workflow before it.
func (g *Graph) AddRemote(r *RemoteCalled, by Call) Node {
	if slices.Contains(g.remotes, r) {
		panic("calls: a remote called workflow added twice")
	}
	r.order = len(g.remotes)
	g.remotes = append(g.remotes, r)
	n := RemoteNode(r)
	g.byName[n] = len(g.files)
	g.files = append(g.files, File{Tree: r.Called.Origin.Tree, Workflow: r.Called.Workflow, Remote: r})
	g.calls[n] = []Call{by}
	return n
}

// Remotes are the remote called workflows of g, in the order added.
func (g *Graph) Remotes() []*RemoteCalled { return g.remotes }
