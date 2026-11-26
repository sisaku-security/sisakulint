package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// EventNamesOf are the names of the events of w's own on
// (taint.OwnEvents), each once, and workflow_call last when w is called: the
// mark of a run whose event its callers decide, which CacheSavesOn reads as
// the caller's choice. A name GitHub does not know is left out.
func EventNamesOf(w *workflow.Workflow) []workflow.EventName {
	evs, called, _ := taint.OwnEvents(w)
	var out []workflow.EventName
	for _, e := range evs {
		if !slices.Contains(out, e.Name()) {
			out = append(out, e.Name())
		}
	}
	if called {
		out = append(out, workflow.EventNameWorkflowCall)
	}
	return out
}

// savesByDefault are the events on which a job that writes no cache-mode
// saves to the cache; pull_request saves to
// the scope of its merge ref, which counts toward the repository's
// limit.
var savesByDefault = []workflow.EventName{
	workflow.EventNamePush, workflow.EventNameWorkflowDispatch, workflow.EventNameRepositoryDispatch,
	workflow.EventNameDelete, workflow.EventNameRegistryPackage, workflow.EventNamePageBuild,
	workflow.EventNameSchedule, workflow.EventNamePullRequest,
}

// CacheSavesOn is whether a job whose cache-mode is jobMode, else the
// workflow's wfMode, may save to the cache on a run of e: by CacheWriteOf,
// then by the event's default. On workflow_call the caller decides, and it
// may let the job save: it is read as saving.
func CacheSavesOn(jobMode, wfMode workflow.Field[workflow.String], e workflow.EventName) bool {
	switch CacheWriteOf(jobMode, wfMode) {
	case analysis.CacheWriteYes:
		return true
	case analysis.CacheWriteNo:
		return false
	}
	return e == workflow.EventNameWorkflowCall || slices.Contains(savesByDefault, e)
}
