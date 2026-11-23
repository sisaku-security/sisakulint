package job

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Job is a job of a workflow and what the rules read of it.
type Job struct {
	Job                workflow.Job
	PrivilegedOn       []analysis.EventActivity // the attacker's privileged events it can run on
	Approval           analysis.Approval
	Environment        facts.EnvironmentName // when ApprovalEnvironment
	TokenWrite         analysis.TokenWrite
	WriteAll           analysis.WriteAll           // where write-all holds for its token
	CalledOnly         bool                        // its workflow runs only when called (workflow_call alone)
	CalledKind         analysis.CalledWorkflowKind // where the reusable workflow it calls is
	CalledRepo         facts.Repo                  // owner/name of the workflow it calls, for UsesRemote
	Secrets            Secrets
	CalledContextReads []CalledContextRead // for a job that calls: those of the called workflows that make it read every secret
	RunnerLabels       []RunnerLabel
	InconclusiveLabels []InconclusiveLabel // of runs-on
}

// Analyze is each job of w, its ifs read in the attacker run table t;
// nil for nil. A job that calls a reusable workflow reads every secret
// with secrets: inherit (AnalyzeIn reads the called workflow).
func Analyze(w *workflow.Workflow, t attacker.Table) []Job {
	return AnalyzeIn(w, t, nil, calls.Node{})
}

// AnalyzeIn is Analyze, w being the workflow of the node self of the call
// graph g: a job that calls a reusable workflow of g whose contents the
// linter has reads what the jobs of that workflow read (calledReader). The
// Secrets of such a job depend on the called workflow: the check after a
// fix compares again the input fixed and those it calls, not those that
// call it, so a fix of a called workflow that changed what it reads would
// not show in the Secrets of its callers (no fix does so now).
func AnalyzeIn(w *workflow.Workflow, t attacker.Table, g *calls.Graph, self calls.Node) []Job {
	if w == nil {
		return nil
	}
	var out []Job
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present {
			continue // not a job, or an id written twice (the model reports it)
		}
		j := je.Value.Value
		x := Job{Job: j, PrivilegedOn: eventsOf(w, j, t), TokenWrite: TokenWriteOf(j.Permissions, w.Permissions)}
		x.Secrets, x.CalledContextReads = newCalledReader(g, self).job(self, w, j, false)
		x.Approval, x.Environment = ApprovalOf(x.PrivilegedOn, &j)
		x.WriteAll = WriteAllOf(j.Permissions, w.Permissions)
		x.CalledOnly = CalledOnly(w)
		x.CalledKind, x.CalledRepo = calledOf(j)
		x.RunnerLabels, x.InconclusiveLabels = runnerLabelsOf(w, j)
		out = append(out, x)
	}
	return out
}
