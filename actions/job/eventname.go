package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

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
// then by the event's default. In a called workflow (called) the caller's
// cache-mode decides, and it may let the job save: it is read as saving.
func CacheSavesOn(jobMode, wfMode workflow.Field[workflow.String], e workflow.EventName, called bool) bool {
	switch CacheWriteOf(jobMode, wfMode) {
	case analysis.CacheWriteYes:
		return true
	case analysis.CacheWriteNo:
		return false
	}
	return called || slices.Contains(savesByDefault, e)
}
