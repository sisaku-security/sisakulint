package github

import (
	"context"
	"encoding/json"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// actionRunsUsing answers action.runs-using: the runs.using of the action
// the runner runs for uses: <repo>/<path>@<ref>, read from the file that
// defines it in the archive the runner downloads (definitionAt): a
// Dockerfile is a Docker container action.
func (r *resolver) actionRunsUsing(ctx context.Context, q facts.ActionRunsUsing) facts.RawAnswer {
	if r.readRunsUsing == nil {
		return unknown("github: no reader of the metadata of an action was given")
	}
	_, name, _, data, ans := r.definitionAt(ctx, q.Repo, q.Path, q.Ref, facts.KindActionRunsUsing)
	if ans.State != facts.StateFound {
		return ans
	}
	using := facts.RunsUsingDocker
	if data != nil {
		var err error
		if using, err = r.readRunsUsing(data); err != nil {
			return unknown("github: the runs.using of " + name.String() + " could not be read: " + err.Error())
		}
	}
	b, _ := json.Marshal(using)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}
