package analysis

// Verdict is what an attacker controls of a reference in a sink.
type Verdict uint8

const (
	NotControlled Verdict = iota
	Controlled            // on the events of the reference
	Inconclusive          // it may be, but the analysis reaches no conclusion (its InconclusiveRefKind)
)

var verdictNames = [...]string{"NotControlled", "Controlled", "Inconclusive"}

func (v Verdict) String() string { return verdictNames[v] }

// InconclusiveRefKind is a kind of reference whose value the analysis
// reaches no conclusion on.
type InconclusiveRefKind uint8

// The kinds of steps and of jobs are each in the order of how little is
// decided of them: the least decided is the greatest.
const (
	InconclusiveRefUnset            InconclusiveRefKind = iota // none: taint gives it to no reference
	InconclusiveRefStepRun                                     // steps.<id>.outputs of a step that runs a script
	InconclusiveRefStepLocalAction                             // of a step that uses a local action (./ in the workspace, $/ in the repository of the action)
	InconclusiveRefStepRemoteAction                            // of a step that uses an action of another repository
	InconclusiveRefStepDocker                                  // of a step that runs a Docker image (docker://)
	InconclusiveRefJob                                         // needs.<id>.outputs of a job of steps
	InconclusiveRefJobLocalCall                                // of a job that calls a reusable workflow of the same repository
	InconclusiveRefJobRemoteCall                               // of a job that calls a reusable workflow of another repository
	InconclusiveRefInputDispatch                               // inputs of a workflow_dispatch, which whoever dispatches chooses
	InconclusiveRefInputCall                                   // inputs of a reusable workflow or a composite action
	InconclusiveRefMatrix                                      // matrix, whose values are not all written in the workflow
	InconclusiveRefEnvUnset                                    // env of a name the workflow does not set, which a step may set at run time
	InconclusiveRefEnvDynamic                                  // env of a level whose env is a whole ${{ }}
	InconclusiveRefEnvWhole                                    // the whole env, or env of a name not known
)

var inconclusiveRefKindNames = [...]string{"", "step-output-run", "step-output-local-action", "step-output-remote-action", "step-output-docker",
	"job-output", "job-output-local-call", "job-output-remote-call", "input-dispatch", "input-call", "matrix",
	"env-unset", "env-dynamic", "env-whole"}

// String is the ID of the kind in the registry of rules
// (lint.InconclusiveKindID).
func (g InconclusiveRefKind) String() string { return inconclusiveRefKindNames[g] }

// InconclusiveWriteKind is a kind of write to an environment file that is
// not followed.
type InconclusiveWriteKind uint8

const (
	InconclusiveWriteUnset         InconclusiveWriteKind = iota // none
	InconclusiveWriteWriterUnknown                              // what a command not known writes to a file command, with what an attacker may control in it
	InconclusiveWriteSubstValue                                 // a $( ) or a value not read written to a file command, with what an attacker may control in it
	InconclusiveWriteExecRedirect                               // exec sends what follows in the script to a file command
	InconclusiveWriteAfterStop                                  // what the script writes to a file command after where it is not followed
)

var inconclusiveWriteKindNames = [...]string{"", "writer-unknown", "subst-value", "exec-redirect", "after-stop"}

// String is the ID of the kind in the registry of rules
// (lint.InconclusiveKindID).
func (g InconclusiveWriteKind) String() string { return inconclusiveWriteKindNames[g] }
