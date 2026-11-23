package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// workflowDefinition answers workflow.definition: the reusable workflow at
// q.Path of the commit q.Ref names, read from the commit (the contents
// API's raw blob), as GitHub runs a reusable workflow of another
// repository from the commit, not from its archive. The ref is resolved
// as git.ref-commit resolves it (refCommitOf), and its answer that is not
// found is the answer; a file the contents API does not find at a commit
// the run read is absent.
func (r *resolver) workflowDefinition(ctx context.Context, q facts.WorkflowDefinition) facts.RawAnswer {
	repo, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	at := r.refCommitOf(ctx, facts.GitRefCommit{Repo: q.Repo, Ref: q.Ref}, facts.KindWorkflowDefinition)
	if at.State != facts.StateFound {
		return at
	}
	var rc facts.RefCommit
	if err := json.Unmarshal(at.Value, &rc); err != nil {
		return unknown("github: the commit of the ref could not be read")
	}
	var parts []string
	for _, s := range strings.Split(q.Path.String(), "/") {
		parts = append(parts, url.PathEscape(s))
	}
	resp, why := r.get(ctx, facts.KindWorkflowDefinition, repo+"contents/"+strings.Join(parts, "/")+"?ref="+rc.SHA.String(), "application/vnd.github.raw+json", maxDefinition+1)
	what := q.Path.String() + " of " + q.Repo.String() + "@" + rc.SHA.String()
	switch {
	case why != "":
		return unknown(why)
	case resp.status == http.StatusNotFound:
		return facts.RawAnswer{State: facts.StateAbsent} // the commit was read with the same token
	case resp.status != http.StatusOK:
		return unknown("github: " + what + " could not be read: HTTP " + strconv.Itoa(resp.status))
	case len(resp.body) > maxDefinition:
		return unknown("github: " + what + " is larger than " + strconv.Itoa(maxDefinition>>20) + " MiB")
	}
	b, err := json.Marshal(facts.WorkflowFile{Commit: rc.SHA, Content: string(resp.body)})
	if err != nil {
		return unknown("github: " + err.Error())
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}
