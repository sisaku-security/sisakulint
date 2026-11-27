package ir

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// DownloadArtifactRepo and Dawidd6Repo are the repositories of the two
// actions whose downloads prcode reads, for the rules, which do not import
// prcode.
var (
	DownloadArtifactRepo = prcode.DownloadArtifactRepo
	Dawidd6Repo          = prcode.Dawidd6Repo
)

// SearchEvents are the events on which a search of runs by
// dawidd6/action-download-artifact may take the attacker's run: every
// event, as the search does not read the event of the job (prcode reads
// such a search on every event the job runs on).
func SearchEvents() []workflow.EventName { return workflow.EventNames() }

func (x *IR) allDownloadSites() []*DownloadSite {
	x.once(SummaryDownloadSite, func() {
		var out []*DownloadSite
		for _, s := range prcode.AnalyzeDownloadsIn(x.callersOf(), x.name, x.workflow, x.action, x.scripts) {
			if len(s.PRCodeOn) > 0 || s.DispatchInput && len(s.DispatchOn) > 0 {
				out = append(out, x.projectDownloadSite(s))
			}
		}
		x.downloadSites = out
	})
	return x.downloadSites
}

// projectDownloadSite is the projection of the site s: its values without
// their positions and pointers, which the handles keep.
func (x *IR) projectDownloadSite(s prcode.DownloadSite) *DownloadSite {
	d := &DownloadSite{
		key:           keyOf(x.paths, x.input, x.tree, s.Step.Base),
		at:            x.handleOf(s.Step.Base),
		usesAt:        x.handleOf(s.Uses.Base),
		dynamic:       s.Dynamic,
		prCodeOn:      s.PRCodeOn,
		dispatchOn:    s.DispatchOn,
		dispatchInput: s.DispatchInput,
		approval:      s.Approval,
		environment:   s.Environment,
		actionsRead:   s.ActionsRead,
		destination:   s.Destination,
		stepPath:      s.Path,
		usesText:      s.Uses.Text(),
	}
	d.automaticApproval = x.automaticApprovalOf(s.PRCodeOn, s.Job, attacker.StepIf(x.workflow, s.Job, s.Step.If))
	for _, r := range s.PRRunRefs {
		at := d.usesAt
		if r.Input != analysis.DownloadInputUses {
			at = x.spanOf(s.Value(r.Input.String()), r.Span)
		}
		d.prRunRefs = append(d.prRunRefs, PRRunRef{Text: r.Text, Input: r.Input, At: at})
	}
	for _, u := range s.SameRunUploads {
		r := SameRunUpload{Text: u.Text, CheckoutAt: x.handleOf(u.Checkout), UploadAt: x.handleOf(u.Upload)}
		for _, n := range u.Unless {
			r.Unless = append(r.Unless, MissingCommit{Repo: n.Repo, SHA: n.SHA, Commit: n.Commit})
		}
		d.sameRunUploads = append(d.sameRunUploads, r)
	}
	for _, v := range s.InconclusiveValues {
		d.inconclusiveValues = append(d.inconclusiveValues, v.Text())
	}
	for _, v := range s.SameRunUnknown {
		d.sameRunUnknown = append(d.sameRunUnknown, v.Text())
	}
	if s.DestinationValue != nil {
		d.destinationText = s.DestinationValue.Text()
	}
	for _, n := range s.MissingCommits {
		d.missingCommits = append(d.missingCommits, MissingCommit{Repo: n.Repo, SHA: n.SHA, Commit: n.Commit})
	}
	d.codeRunSteps = x.codeRunSteps(s.CodeRunSteps)
	x.downloadSiteOf[d] = s
	return d
}

// runnerTempPath is the fix that puts the files of d under runner.temp:
// path ${{ runner.temp }}/artifacts in its with, made when there is none.
// A path written is left as it is: the steps after it may read it.
func (d *DownloadSite) runnerTempPath(q *RuleAccess) FixPlan {
	site := q.ir.downloadSiteOf[d]
	if !site.PathFixHolds() {
		return FixPlan{NoFix: manual("this release of actions/download-artifact (4.0.0 to 4.1.2, or a commit not known as a later one) writes the paths of the zip anywhere, .. too; move to v4.1.3 or later, then set path: ${{ runner.temp }}/artifacts")}
	}
	s := site.Step
	if len(s.Via) > 0 || s.With.Status == workflow.Present && len(s.With.Value.Via) > 0 {
		return FixPlan{NoFix: form("the step or its with is reached through an alias; set path: ${{ runner.temp }}/artifacts by hand")}
	}
	if _, ok := s.Node.Anchor(); ok || s.With.Status == workflow.Present && hasAnchor(s.With.Value.Node) {
		return FixPlan{NoFix: form("the step or its with has an anchor, whose aliases would change too; set path by hand where it is needed")}
	}
	const value = "${{ runner.temp }}/artifacts"
	ed := &q.ir.editor
	var out edit.Edit
	var err error
	switch s.With.Status {
	case workflow.Absent:
		out, err = ed.Insert(s.Node, edit.After("uses"), edit.Map{{Key: "with", Value: edit.Map{{Key: "path", Value: edit.Str(value)}}}})
	case workflow.Present:
		if _, ok := s.With.Value.Lookup("path"); ok {
			return FixPlan{NoFix: manual("the download has a path, which the steps after it may read; move it out of the workspace, to " + value + ", and those steps with it")}
		}
		out, err = ed.Insert(s.With.Value.Node, edit.Last(), edit.Map{{Key: "path", Value: edit.Str(value)}})
	default:
		return FixPlan{NoFix: form("with is not a mapping; set path: " + value + " by hand")}
	}
	if err != nil {
		return FixPlan{NoFix: form("path cannot be written here (" + err.Error() + "); set it to " + value + " by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixRunnerTempPath, Title: "put the artifact's files out of the workspace: path: " + value, Edits: []edit.Edit{out}, SideEffects: []SideEffect{SideEffectArtifactPathMoved}}}
}
