package workflow

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Workflow is a workflow file (workflow-root-strict).
type Workflow struct {
	Base
	Name         Field[String]
	RunName      Field[String]
	On           Field[On]
	Permissions  Field[Permissions]
	CacheMode    Field[String] // cache-mode, as written: the schema checks the value
	Env          Field[Map[String]]
	DefaultShell Field[String] // defaults.run.shell
	// DefaultWorkingDirectory (defaults.run.working-directory) and
	// Concurrency are as written: the schema checks the values
	DefaultWorkingDirectory Field[String]
	Concurrency             Field[Concurrency]
	Jobs                    Field[Map[Job]]
}

func (r *reader) readWorkflow(w *Workflow, content cst.Node) {
	v := r.value(content, pos{}, dWorkflowRootStrict)
	if v.st != Present {
		return
	}
	ents, _, _ := r.mapping(v, dWorkflowRootStrict)
	p := v.p
	w.Base = Base{Node: v.n, Via: p.via}
	w.Name = r.str(get(ents, "name"), p)
	w.RunName = r.str(get(ents, "run-name"), p)
	w.On = r.readOn(get(ents, "on"), p)
	w.Permissions = r.permissions(get(ents, "permissions"), p)
	w.CacheMode = r.str(get(ents, "cache-mode"), p)
	w.Env = r.strMap(get(ents, "env"), p)
	w.DefaultShell, w.DefaultWorkingDirectory = r.defaultRun(get(ents, "defaults"), p)
	w.Concurrency = r.concurrency(get(ents, "concurrency"), p)
	w.Jobs = readMap(r, get(ents, "jobs"), p, r.job)
	r.checkNeeds(w.Jobs)
}

// NeedClosure is j and the jobs of w that j needs, each once by its ID, j
// first, following the needs of a job while follow is true for the job.
// A name of needs is looked up as GitHub compares keys (Map.Lookup), and a
// name that names no job is skipped: GitHub does not accept the workflow.
// With no w, j alone.
func NeedClosure(w *Workflow, j *Job, follow func(*Job) bool) []Job {
	var out []Job
	seen := map[string]bool{}
	var visit func(j *Job)
	visit = func(j *Job) {
		id := expr.FoldName(j.ID.AsString())
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, *j)
		if !follow(j) || w == nil || w.Jobs.Status != Present || j.Needs.Status != Present {
			return
		}
		for _, n := range j.Needs.Value.Items {
			if e, ok := w.Jobs.Value.Lookup(n.AsString()); ok && e.Value.Status == Present {
				need := e.Value.Value
				visit(&need)
			}
		}
	}
	visit(j)
	return out
}
