// Package calls finds, among the inputs of a run, which job or step calls
// which workflow or composite action of the same repository (uses: ./…,
// $/…, and an owner/repo/path@ref that names the repository itself), so
// that the events and the inputs of a called one are read from its
// callers. A node of the graph is an input, or a remote called workflow: a
// reusable workflow of another repository that the fact
// workflow.definition answers, which the engine adds (AddRemote) for each
// chain of calls from a job of an input, with that job's call, or the call
// of the job of the remote called workflow before it, as its one caller.
// It reads models only; what a value of with is, is actions/taint's.
//
// Where things are:
//
//	node.go     Node (an input or a remote called workflow), RemoteCalled, CompareNodes
//	graph.go    File, Call, Graph: the calls by the node called (CallsOf) and by the caller (CalledBy), Coverage, Dependents, AddRemote, Remotes
//	check.go    Diagnostics: GitHub's checks of a job's call of a workflow among the inputs (workflow.CheckCall)
//	resolve.go  the calls of an input, the path a uses names, whether a step's ./… is the input (Resolved), IsCheckout, CheckoutRef
package calls
