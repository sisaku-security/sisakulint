package calls

import (
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Node is a file of the call graph: an input of the run, or a remote
// called workflow. Two nodes are the same file exactly when they are ==.
type Node struct {
	input  facts.InputPath
	remote *RemoteCalled
}

// InputNode is the node of the input named n.
func InputNode(n facts.InputPath) Node { return Node{input: n} }

// RemoteNode is the node of the remote called workflow r.
func RemoteNode(r *RemoteCalled) Node { return Node{remote: r} }

// Input is the name of the input n is, when it is one.
func (n Node) Input() (facts.InputPath, bool) {
	return n.input, n.remote == nil && !n.input.IsZero()
}

// Remote is the remote called workflow n is, when it is one.
func (n Node) Remote() (*RemoteCalled, bool) { return n.remote, n.remote != nil }

// IsZero is whether n is no file.
func (n Node) IsZero() bool { return n.remote == nil && n.input.IsZero() }

// String is the name of an input, or what names a remote called workflow.
func (n Node) String() string {
	if n.remote != nil {
		return n.remote.String()
	}
	return n.input.String()
}

// RemoteCalled is a remote called workflow: a reusable workflow of another
// repository that the fact workflow.definition answers, read for one chain
// of calls from a job of an input. Top and TopJob are the input and its job
// the chain starts at: the job whose uses the findings in it are reported
// at.
type RemoteCalled struct {
	Called composite.Called
	Top    facts.InputPath
	TopJob *workflow.Job
	Parent *RemoteCalled // the remote called workflow whose job calls it; nil when the job of the input does
	order  int           // the order the graph added it in
}

// String names r: the file the answer is of, and the input and the job the
// chain starts at.
func (r *RemoteCalled) String() string {
	var name string
	if q, ok := r.Called.Origin.Query.(facts.WorkflowDefinition); ok {
		name = q.Repo.String() + "/" + q.Path.String()
	}
	if n := len(r.Called.Chain); n > 0 && r.Called.Chain[n-1].Commit.String() != "" {
		name += " at " + r.Called.Chain[n-1].Commit.String()
	}
	if r.TopJob != nil {
		name += ", called from the job " + r.TopJob.ID.AsString() + " of " + r.Top.String()
	}
	return name
}

// CompareNodes orders nodes: the inputs by name, then the remote called
// workflows in the order they are added.
func CompareNodes(a, b Node) int {
	switch {
	case a.remote == nil && b.remote == nil:
		return facts.CompareInputPaths(a.input, b.input)
	case a.remote == nil:
		return -1
	case b.remote == nil:
		return 1
	}
	return a.remote.order - b.remote.order
}
