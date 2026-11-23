package job

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TokenWriteOf is whether the job's GITHUB_TOKEN may write, by the job's
// permissions, else the workflow's: a scope
// other than id-token written write, write-all, or a ${{ }} GitHub
// evaluates. A folded literal (${{ 'read-all' }}) is its string, as GitHub
// reads it.
func TokenWriteOf(job, wf workflow.Field[workflow.Permissions]) analysis.TokenWrite {
	p := job
	if p.Status == workflow.Absent {
		p = wf
	}
	switch p.Status {
	case workflow.Absent:
		return analysis.TokenWriteUnwritten
	case workflow.Present:
	default:
		return analysis.TokenWriteYes // a ${{ }}, or what the model reports
	}
	if all := p.Value.All; p.Value.Scopes == nil && (all.Parts != nil || all.Text() != "") {
		if all.HasExpr() || strings.EqualFold(strings.TrimSpace(all.AsString()), "write-all") {
			return analysis.TokenWriteYes
		}
		return analysis.TokenWriteNo
	}
	for _, s := range p.Value.Scopes {
		if strings.EqualFold(s.Name.AsString(), "id-token") {
			continue
		}
		if s.Access.HasExpr() || strings.EqualFold(strings.TrimSpace(s.Access.AsString()), "write") {
			return analysis.TokenWriteYes
		}
	}
	return analysis.TokenWriteNo
}

// WriteAllOf is where write-all holds for the job's GITHUB_TOKEN: the job's
// permissions, else the workflow's. The model reads write-all, also folded
// from ${{ 'write-all' }}, which GitHub takes; it rejects another case
// (Write-All), which GitHub does not run.
func WriteAllOf(job, wf workflow.Field[workflow.Permissions]) analysis.WriteAll {
	p, at := job, analysis.WriteAllJob
	if p.Status == workflow.Absent {
		p, at = wf, analysis.WriteAllWorkflow
	}
	if p.Status != workflow.Present || p.Value.Scopes != nil {
		return analysis.WriteAllNo
	}
	if strings.TrimSpace(p.Value.All.AsString()) == "write-all" {
		return at
	}
	return analysis.WriteAllNo
}

// ActionsReadOf is whether the GITHUB_TOKEN of a job whose permissions are
// job, else the workflow's wf, may read the artifacts of another run: the
// scope actions read or write, read-all or write-all. Permissions written
// without actions set it to none ("all of those that are not specified
// are set to none", https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).
// A folded literal is its string, as GitHub reads it.
func ActionsReadOf(job, wf workflow.Field[workflow.Permissions]) analysis.ActionsRead {
	p := job
	if p.Status == workflow.Absent {
		p = wf
	}
	switch p.Status {
	case workflow.Absent:
		return analysis.ActionsReadUnwritten
	case workflow.Present:
	default:
		return analysis.ActionsReadYes // a ${{ }}, or what the model reports
	}
	if all := p.Value.All; p.Value.Scopes == nil && (all.Parts != nil || all.Text() != "") {
		v := strings.ToLower(strings.TrimSpace(all.AsString()))
		if all.HasExpr() || v == "read-all" || v == "write-all" {
			return analysis.ActionsReadYes
		}
		return analysis.ActionsReadNo
	}
	for _, s := range p.Value.Scopes {
		if !strings.EqualFold(s.Name.AsString(), "actions") {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(s.Access.AsString()))
		if s.Access.HasExpr() || v == "read" || v == "write" {
			return analysis.ActionsReadYes
		}
	}
	return analysis.ActionsReadNo
}

// PullRequestsWriteOf is whether the GITHUB_TOKEN of a job whose
// permissions are job, else the workflow's wf, may write the scope
// pull-requests: pull-requests write or write-all. Permissions written
// without it set it to none, as ActionsReadOf says. A ${{ }} is read as
// writing, so that a rule reports no finding on what it cannot read.
func PullRequestsWriteOf(job, wf workflow.Field[workflow.Permissions]) analysis.PullRequestsWrite {
	p := job
	if p.Status == workflow.Absent {
		p = wf
	}
	switch p.Status {
	case workflow.Absent:
		return analysis.PullRequestsWriteUnwritten
	case workflow.Present:
	default:
		return analysis.PullRequestsWriteYes // a ${{ }}, or what the model reports
	}
	if all := p.Value.All; p.Value.Scopes == nil && (all.Parts != nil || all.Text() != "") {
		if all.HasExpr() || strings.EqualFold(strings.TrimSpace(all.AsString()), "write-all") {
			return analysis.PullRequestsWriteYes
		}
		return analysis.PullRequestsWriteNo
	}
	for _, s := range p.Value.Scopes {
		if !strings.EqualFold(s.Name.AsString(), "pull-requests") {
			continue
		}
		if s.Access.HasExpr() || strings.EqualFold(strings.TrimSpace(s.Access.AsString()), "write") {
			return analysis.PullRequestsWriteYes
		}
	}
	return analysis.PullRequestsWriteNo
}

// CacheWriteOf is whether the job may save to the cache by its cache-mode,
// else the workflow's: write and write-only save, read and
// none do not. A literal ${{ }} is its string. Another ${{ }} is read
// as saving, and a value GitHub does not take as written; GitHub
// refuses to run either, so neither reading misses a harm.
func CacheWriteOf(job, wf workflow.Field[workflow.String]) analysis.CacheWrite {
	m := job
	if m.Status == workflow.Absent {
		m = wf
	}
	switch {
	case m.Status == workflow.Absent:
		return analysis.CacheWriteUnwritten
	case m.Status == workflow.Dynamic, m.Value.HasExpr():
		return analysis.CacheWriteYes
	}
	mode, ok := analysis.ParseCacheMode(m.Value.AsString())
	switch {
	case !ok:
		return analysis.CacheWriteUnwritten
	case mode.Saves():
		return analysis.CacheWriteYes
	}
	return analysis.CacheWriteNo
}
