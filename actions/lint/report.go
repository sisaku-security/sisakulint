package lint

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gh-intel/sisakulint/actions/ir"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// ReportSchema is the value of schema in the JSON of a report.
const ReportSchema = "sisakulint/report/v0"

// Report is what a run found.
type Report struct {
	Inputs   []Input
	Complete bool      // the inputs are the whole repository
	Excluded []Exclude // the paths left out (Inputs.Excluded)
	// Reported are the inputs whose places the report is about
	// (Inputs.Reported); nil is every input, and the JSON writes their
	// names. Run keeps every place, so that Accept matches the places of
	// the other inputs too; Narrow drops them, and the JSON writes only
	// what Narrow keeps. Inputs has every input of the run.
	Reported []facts.InputPath
	// Counted are the inputs the exit code counts (Classify), of their
	// states and their places; nil is Reported. A pull request run with
	// PATHs reports the PATHs and counts every changed input.
	Counted      []facts.InputPath
	Rules        []RuleRef
	SkippedRules []RuleID // the rules and quality rules the registry left out (Registry.Select): those not selected, and those whose DefaultRun does not hold (Registry.NotRunByDefault); by ID
	// Findings are the findings of the rules, of every certainty
	// (confirmed, conditional and inconclusive: FindingsWith), in the order
	// of their places. A
	// finding whose certainty is inconclusive that no acceptance matched
	// sets bit 8 in Classify when the severity of its rule is at or above
	// the threshold.
	Findings []Finding
	// QualityRules are the quality rules that ran, by ID; QualityFindings,
	// their findings, in the order of their places. A quality finding sets no
	// bit of the exit code (Classify).
	QualityRules    []RuleID
	QualityFindings []QualityFinding
	Facts           []facts.Entry // what the rules asked, and the answers
	Errors          []RunError
	Fix             *FixResult // nil unless the fixes were applied; Run leaves it nil
	// Remote is what a run read of a repository of GitHub (--remote of the
	// CLI); nil for files on disk. Run leaves it nil.
	Remote *RemoteRevision
	// AddedAttackers are the attackers the run added (RunAdded), each once,
	// in their order; nil for a run that adds none
	AddedAttackers []AddedAttacker

	unreadCalls map[facts.InputPath][]facts.InputPath // the inputs not read or not valid that an input calls, by caller (Run)
	// outside are the places of the counted inputs that Narrow left out of
	// the arrays: Classify and Unreported count them.
	outside outsidePlaces
}

type outsidePlaces struct {
	findings []Finding
	quality  []QualityFinding
}

// Unreported is how many places of the counted inputs Narrow left out of
// the arrays (UnreportedCount).
func (r Report) Unreported() UnreportedCount {
	n := 0
	for _, f := range r.outside.findings {
		if f.Certainty == CertaintyInconclusive {
			n++
		}
	}
	return UnreportedCount{Findings: len(r.outside.findings), QualityFindings: len(r.outside.quality), Inconclusive: n}
}

// FindingsWith are the findings of r whose certainty is one of cs, in the
// order of r.Findings.
func (r Report) FindingsWith(cs ...Certainty) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if slices.Contains(cs, f.Certainty) {
			out = append(out, f)
		}
	}
	return out
}

// ReportedInputs are the inputs of r whose places r reports
// (Report.Reported): what Classify counts.
func (r Report) ReportedInputs() []Input {
	return r.inputsNamed(r.Reported)
}

// CountedInputs are the inputs of r whose states and places the exit code
// counts (Report.Counted).
func (r Report) CountedInputs() []Input {
	return r.inputsNamed(r.countedNames())
}

// countedNames are Counted, or Reported when Counted is nil.
func (r Report) countedNames() []facts.InputPath {
	if r.Counted != nil {
		return r.Counted
	}
	return r.Reported
}

// inputsNamed are the inputs of r named in names; nil names is every one.
func (r Report) inputsNamed(names []facts.InputPath) []Input {
	if names == nil {
		return r.Inputs
	}
	var out []Input
	for _, i := range r.Inputs {
		if slices.Contains(names, i.Name) {
			out = append(out, i)
		}
	}
	return out
}

// reportedNames are the names of the reported inputs: Reported, or the
// name of each input when it is nil.
func (r Report) reportedNames() []facts.InputPath {
	if r.Reported != nil {
		return r.Reported
	}
	out := []facts.InputPath{}
	for _, i := range r.Inputs {
		out = append(out, i.Name)
	}
	return out
}

// Narrow is r with only the places of its reported inputs
// (Report.Reported): a finding or a quality finding whose location,
// evidence or related place is in one of them, whatever the certainty of
// the finding. The evidence counts because a finding may be where a
// value is used, in an input not reported, and come of a reported input,
// where the value is given (a caller's with). A place in a file of a fact
// is in no input. Nil Reported keeps every place.
func (r Report) Narrow() Report {
	out := r.narrowTo(r.Reported)
	if r.Counted == nil || r.Reported == nil {
		return out
	}
	reported := placeTest(r.Reported)
	counted := placeTest(r.Counted)
	out.outside = outsidePlaces{slices.Clone(r.outside.findings), slices.Clone(r.outside.quality)}
	for _, f := range r.Findings {
		if !reported(f.FindingDraft) && counted(f.FindingDraft) {
			out.outside.findings = append(out.outside.findings, f)
		}
	}
	for _, f := range r.QualityFindings {
		if !reported(f.FindingDraft) && counted(f.FindingDraft) {
			out.outside.quality = append(out.outside.quality, f)
		}
	}
	return out
}

// In is whether f is of the inputs names: its location, a place of its
// evidence or a related place is in one of them.
func (f FindingDraft) In(names []facts.InputPath) bool { return placeTest(names)(f) }

// placeTest is whether a finding is of the inputs names (its location,
// evidence or related place).
func placeTest(names []facts.InputPath) func(FindingDraft) bool {
	in := func(l Location) bool { return !l.File.Input.IsZero() && slices.Contains(names, l.File.Input) }
	return func(d FindingDraft) bool {
		return in(d.Location) || slices.ContainsFunc(d.Evidence, func(x Related) bool { return in(x.Location) }) || slices.ContainsFunc(d.Related, func(x Related) bool { return in(x.Location) })
	}
}

// narrowTo is r with only the places of the inputs names (Narrow); nil
// names keeps every place.
func (r Report) narrowTo(names []facts.InputPath) Report {
	if names == nil {
		return r
	}
	touches := placeTest(names)
	var findings []Finding
	for _, f := range r.Findings {
		if touches(f.FindingDraft) {
			findings = append(findings, f)
		}
	}
	var quality []QualityFinding
	for _, f := range r.QualityFindings {
		if touches(f.FindingDraft) {
			quality = append(quality, f)
		}
	}
	r.Findings, r.QualityFindings = findings, quality
	return r
}

// FixResult is what came of applying the fixes of a report to the files.
// It counts for nothing in Classify: the findings are of the files before
// the fixes.
type FixResult struct {
	Safety  Safety            // the fixes asked for: SafetySafe, or SafetyReview for all
	Written []facts.InputPath // the files written, in the order of their names
	Error   string            // empty when every file to fix was written
	// UncheckedRules are the rules not run a field of which the fixes change
	// (ApplyFixes): the fixes were not checked against them.
	UncheckedRules []Unchecked
}

// RemoteRevision is a repository of GitHub as a run read it (the JSON
// remote_revision).
type RemoteRevision struct {
	Repository  facts.Repo
	Ref         string // after @ of --remote; empty is the default branch, and a pull request
	Commit      facts.SHA
	Tree        facts.SHA
	ReadFiles   []RemoteFile // in the order of their paths
	PullRequest *PullRequestRevision
}

// RemoteFile is an entry of the tree whose contents a run read or tried to
// read: its path, its blob and its mode.
type RemoteFile struct {
	Path facts.InputPath
	Blob facts.SHA
	Mode string
}

// PullRequestRevision is the pull request a run read (--pull-request).
type PullRequestRevision struct {
	Number    int
	Base      facts.SHA // the commit of the base branch when the run read it
	MergeBase facts.SHA // the merge base of the head and Base
	BehindBy  int       // the commits Base has that the head has not
	// ChangedInputs are the inputs the pull request changes, those under
	// --exclude too, in order.
	ChangedInputs []facts.InputPath
	// UnreportedCount is the places of the counted inputs that the PATHs
	// left out of the report (Report.Unreported).
	UnreportedCount UnreportedCount
	// BaseChangeCount is how many paths the base changed after the merge
	// base where an input may be or that the run read: what the head does
	// not have, and the merge would.
	BaseChangeCount int
	// AcceptedCount is the inconclusive places in the changed inputs that
	// an acceptance matched: a pull request may change what is around an
	// accepted place, which the acceptance does not see.
	AcceptedCount int
}

// UnreportedCount is how many places of each array the report does not
// have, of the inputs it counts but does not report.
type UnreportedCount struct {
	Findings        int `json:"findings"`
	QualityFindings int `json:"quality_findings"`
	Inconclusive    int `json:"inconclusive"`
}

func (p PullRequestRevision) MarshalJSON() ([]byte, error) {
	return marshal(struct {
		Number          int               `json:"number"`
		Base            facts.SHA         `json:"base"`
		MergeBase       facts.SHA         `json:"merge_base"`
		BehindBy        int               `json:"behind_by"`
		ChangedInputs   []facts.InputPath `json:"changed_inputs"`
		UnreportedCount UnreportedCount   `json:"unreported_count"`
		BaseChangeCount int               `json:"base_change_count"`
		AcceptedCount   int               `json:"accepted_count"`
	}{p.Number, p.Base, p.MergeBase, p.BehindBy, nonNil(p.ChangedInputs), p.UnreportedCount, p.BaseChangeCount, p.AcceptedCount})
}

func (r RemoteRevision) MarshalJSON() ([]byte, error) {
	type fileJSON struct {
		Path facts.InputPath `json:"path"`
		Blob facts.SHA       `json:"blob"`
		Mode string          `json:"mode"`
	}
	out := struct {
		Repository  facts.Repo           `json:"repository"`
		Ref         *string              `json:"ref"`
		Commit      facts.SHA            `json:"commit"`
		Tree        facts.SHA            `json:"tree"`
		ReadFiles   []fileJSON           `json:"read_files"`
		PullRequest *PullRequestRevision `json:"pull_request"`
	}{Repository: r.Repository, Commit: r.Commit, Tree: r.Tree, ReadFiles: []fileJSON{}, PullRequest: r.PullRequest}
	if r.Ref != "" {
		out.Ref = &r.Ref
	}
	for _, f := range r.ReadFiles {
		out.ReadFiles = append(out.ReadFiles, fileJSON(f))
	}
	return marshal(out)
}

// RuleRef is a rule that ran.
type RuleRef struct {
	ID       RuleID
	Severity Severity
}

// Finding is a finding as the engine finished it.
type Finding struct {
	FindingDraft
	Severity    Severity // from the registry of rules
	Certainty   Certainty
	Fingerprint Fingerprint
	Consequence string // why it is bad: of its kind, from the registry of rules
	Remedy      string // what a person does about it: of its kind, too
	// AddedAttackers mark a finding that a run adding no attacker does not
	// report in this form (RunAdded): the added attackers that alone give
	// it, or all of them when only together
	AddedAttackers []AddedAttacker
	// KeyPath, SpanText and SpanLines are what an acceptance names the
	// place of the finding by (Location.KeyPath and identityText); the
	// engine fills them for every finding.
	KeyPath   KeyPath
	SpanText  string
	SpanLines string
	// InconclusiveKind is the inconclusive kind of a finding whose
	// certainty is CertaintyInconclusive, of its rule's
	// Meta.InconclusiveKinds; then Args is nil, and Note is what the rule
	// said of the place, or the text of the kind when the rule said
	// nothing. Zero, with no Note, for the other findings.
	InconclusiveKind InconclusiveKindID
	Note             string
	// Acceptance is the acceptance that matched the place of a finding
	// whose certainty is CertaintyInconclusive (Accept); nil when none did,
	// and for the other findings.
	Acceptance *Acceptance

	fixTree *cst.Tree // the tree of the input whose check gave the fixes
}

// Detected is what f says is detected: of a finding whose certainty is
// CertaintyInconclusive, its Note; of the others, made of its Args.
func (f Finding) Detected() string {
	if f.Certainty == CertaintyInconclusive {
		return f.Note
	}
	return f.FindingDraft.Detected()
}

// KindText is the ID of the kind of f, as args.kind_id of the JSON writes
// it: <rule>.<kind> of its finding kind, or, of a finding whose certainty is
// CertaintyInconclusive, of its inconclusive kind.
func (f Finding) KindText() string {
	if f.Certainty == CertaintyInconclusive {
		return InconclusiveKindText(f.Rule, f.InconclusiveKind)
	}
	return f.Args.KindID().String()
}

// InconclusiveKindText is the kind of a finding of the inconclusive kind k
// of the rule id, as args.kind_id writes it: <rule>.<kind>, in the form of
// the text of a FindingKindID. The registry refuses an inconclusive kind
// with the name of a finding kind of its rule (checkUndetectedForms), so
// the two never meet.
func InconclusiveKindText(id RuleID, k InconclusiveKindID) string {
	return id.String() + "." + k.String()
}

// FixInput is the input of in that the edits of the Fix of f are in: the
// input whose check gave the fix. It is false when f has no Fix, or was not
// made by Run from in.
func (f Finding) FixInput(in Inputs) (Input, bool) {
	if f.Fix == nil || f.fixTree == nil {
		return Input{}, false
	}
	for _, x := range in.List {
		if x.Tree == f.fixTree {
			return x, true
		}
	}
	return Input{}, false
}

// Certainty is whether a finding holds, or holds if its condition does
// ($defs/certainty of schema/report-v0.json).
type Certainty uint8

// RunError is an internal error: a rule that failed, a finding or a fix
// that broke the contract.
type RunError struct {
	Rule    RuleID          // zero when it is not about one rule
	Input   facts.InputPath // zero when it is not about one input
	Message string
}

type spanJSON struct {
	Start  int `json:"start"`
	End    int `json:"end"`
	Line   int `json:"line"`
	Column int `json:"column"`
}

func spanOf(t *cst.Tree, s cst.Span) spanJSON {
	p := t.Position(s.Start)
	return spanJSON{s.Start, s.End, p.Line, p.Column}
}

func (l Location) MarshalJSON() ([]byte, error) {
	type fileJSON struct {
		Input *facts.InputPath `json:"input,omitempty"`
		Fact  json.RawMessage  `json:"query,omitempty"`
	}
	var file fileJSON
	if l.File.Query != nil {
		q, err := facts.EncodeQuery(l.File.Query)
		if err != nil {
			return nil, err
		}
		file.Fact = q
	} else {
		n := l.File.Input
		file.Input = &n
	}
	out := struct {
		File fileJSON `json:"file"`
		spanJSON
		Exact bool       `json:"exact"`
		Via   []spanJSON `json:"via"`
	}{File: file, Exact: l.Exact, Via: []spanJSON{}}
	if l.tree == nil {
		return nil, errors.New("a location not made by At or AtSpan")
	}
	out.spanJSON = spanOf(l.tree, l.Span)
	for _, v := range l.Via {
		out.Via = append(out.Via, spanOf(l.tree, v))
	}
	return marshal(out)
}

func (r Related) MarshalJSON() ([]byte, error) {
	return marshal(struct {
		At   Location `json:"location"`
		Note string   `json:"note"`
	}{r.Location, r.Note})
}

type editJSON struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

type fixJSON struct {
	Kind        FixKindID       `json:"kind_id"`
	Title       string          `json:"title"`
	SideEffects []ir.SideEffect `json:"side_effects"`
	Edits       []editJSON      `json:"edits"`
}

func (r Finding) MarshalJSON() ([]byte, error) {
	type noFixJSON struct {
		Reason ir.NoFixReason    `json:"reason"`
		Facts  []json.RawMessage `json:"queries"`
		Note   string            `json:"note"`
	}
	type acceptanceJSON struct {
		Reason string `json:"reason"`
	}
	out := struct {
		Rule        RuleID          `json:"rule"`
		Severity    Severity        `json:"severity"`
		Certainty   Certainty       `json:"certainty"`
		At          Location        `json:"location"`
		Args        json.Marshaler  `json:"args"`
		Detected    string          `json:"detected"`
		Impact      string          `json:"consequence"`
		Remedy      string          `json:"remedy"`
		Related     []Related       `json:"related"`
		Evidence    []Related       `json:"evidence"`
		Condition   *Condition      `json:"condition,omitempty"`
		Fix         *fixJSON        `json:"fix,omitempty"`
		NoFix       *noFixJSON      `json:"no_fix,omitempty"`
		KeyPath     KeyPath         `json:"key_path"`
		SpanText    string          `json:"span_text"`
		SpanLines   string          `json:"span_lines"`
		Acceptance  *acceptanceJSON `json:"acceptance,omitempty"`
		Fingerprint Fingerprint     `json:"fingerprint"`
		Added       []AddedAttacker `json:"added_attackers,omitempty"`
	}{
		Rule: r.Rule, Severity: r.Severity, Certainty: r.Certainty, At: r.Location, Args: r.Args, Detected: r.Detected(), Impact: r.Consequence, Remedy: r.Remedy,
		Related: nonNil(r.Related), Evidence: nonNil(r.Evidence), Condition: r.Condition,
		KeyPath: r.KeyPath, SpanText: r.SpanText, SpanLines: r.SpanLines,
		Fingerprint: r.Fingerprint, Added: r.AddedAttackers,
	}
	if r.Certainty == CertaintyInconclusive {
		out.Args = inconclusiveArgs{InconclusiveKindText(r.Rule, r.InconclusiveKind)}
	}
	if a := r.Acceptance; a != nil {
		out.Acceptance = &acceptanceJSON{a.Reason}
	}
	if f := r.Fix; f != nil {
		if r.fixTree == nil {
			return nil, errors.New("a fix without the tree it edits (a Finding not made by Run)")
		}
		src := r.fixTree.Bytes()
		fj := &fixJSON{Kind: f.KindID, Title: f.Title, SideEffects: nonNil(f.SideEffects), Edits: []editJSON{}}
		for _, e := range f.Edits {
			fj.Edits = append(fj.Edits, editJSON{e.Span.Start, e.Span.End, string(src[e.Span.Start:e.Span.End]), string(e.New)})
		}
		out.Fix = fj
	}
	if r.NoFix != nil {
		n := &noFixJSON{Reason: r.NoFix.Reason, Facts: []json.RawMessage{}, Note: r.NoFix.Note}
		for _, q := range r.NoFix.Queries {
			b, err := facts.EncodeQuery(q)
			if err != nil {
				return nil, err
			}
			n.Facts = append(n.Facts, b)
		}
		out.NoFix = n
	}
	return marshal(out)
}

// inconclusiveArgs are the args of a finding whose certainty is
// CertaintyInconclusive: only its kind, <rule>.<kind> (InconclusiveKindText).
type inconclusiveArgs struct{ kind string }

func (a inconclusiveArgs) MarshalJSON() ([]byte, error) {
	return marshal(struct {
		Kind string `json:"kind_id"`
	}{a.kind})
}

func (f QualityFinding) MarshalJSON() ([]byte, error) {
	return marshal(struct {
		Rule        RuleID      `json:"rule"`
		Certainty   Certainty   `json:"certainty"`
		At          Location    `json:"location"`
		Args        FindingArgs `json:"args"`
		Detected    string      `json:"detected"`
		Consequence string      `json:"consequence"`
		Remedy      string      `json:"remedy"`
		Related     []Related   `json:"related"`
		Evidence    []Related   `json:"evidence"`
		Condition   *Condition  `json:"condition,omitempty"`
		Fingerprint Fingerprint `json:"fingerprint"`
	}{f.Rule, f.Certainty, f.Location, f.Args, f.Detected(), f.Consequence, f.Remedy, nonNil(f.Related), nonNil(f.Evidence), f.Condition, f.Fingerprint})
}

func (r Report) MarshalJSON() ([]byte, error) {
	r = r.Narrow() // reported_inputs says which places the arrays have
	type diagJSON struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		spanJSON
	}
	type inputJSON struct {
		Name        facts.InputPath `json:"name"`
		Kind        InputKind       `json:"input_kind"`
		State       string          `json:"state"`
		Reason      string          `json:"reason,omitempty"`
		Diagnostics []diagJSON      `json:"diagnostics"`
	}
	type ruleJSON struct {
		ID       RuleID   `json:"id"`
		Severity Severity `json:"severity"`
	}
	type errorJSON struct {
		Rule    *RuleID          `json:"rule,omitempty"`
		Input   *facts.InputPath `json:"input,omitempty"`
		Message string           `json:"message"`
	}
	out := struct {
		Schema       string            `json:"schema"`
		Inputs       []inputJSON       `json:"inputs"`
		Complete     bool              `json:"complete"`
		Excluded     []Exclude         `json:"excluded"`
		Reported     []facts.InputPath `json:"reported_inputs"`
		Rules        []ruleJSON        `json:"rules"`
		Skipped      []RuleID          `json:"skipped_rules"`
		Findings     []Finding         `json:"findings"`
		QualityRules []RuleID          `json:"quality_rules"`
		Quality      []QualityFinding  `json:"quality_findings"`
		Facts        []facts.Entry     `json:"facts"`
		Errors       []errorJSON       `json:"errors"`
		Remote       *RemoteRevision   `json:"remote_revision"`
		Fix          *fixResultJSON    `json:"fix,omitempty"`
		Added        []AddedAttacker   `json:"added_attackers,omitempty"`
	}{Added: r.AddedAttackers, Remote: r.Remote, Schema: ReportSchema, Inputs: []inputJSON{}, Complete: r.Complete, Excluded: nonNil(r.Excluded), Reported: r.reportedNames(), Rules: []ruleJSON{}, Skipped: nonNil(r.SkippedRules),
		Findings: nonNil(r.Findings), QualityRules: nonNil(r.QualityRules), Quality: nonNil(r.QualityFindings), Facts: nonNil(r.Facts), Errors: []errorJSON{}}
	for _, i := range r.Inputs {
		ij := inputJSON{Name: i.Name, Kind: i.InputKind, State: i.State.String(), Reason: i.Reason, Diagnostics: []diagJSON{}}
		for _, d := range i.Diagnostics {
			ij.Diagnostics = append(ij.Diagnostics, diagJSON{d.Code.String(), d.Msg, spanOf(i.Tree, d.Span)})
		}
		out.Inputs = append(out.Inputs, ij)
	}
	for _, x := range r.Rules {
		out.Rules = append(out.Rules, ruleJSON{x.ID, x.Severity})
	}
	for _, e := range r.Errors {
		ej := errorJSON{Message: e.Message}
		if !e.Rule.IsZero() {
			ej.Rule = &e.Rule
		}
		if !e.Input.IsZero() {
			ej.Input = &e.Input
		}
		out.Errors = append(out.Errors, ej)
	}
	if f := r.Fix; f != nil {
		if !f.Safety.valid() {
			return nil, errors.New("a FixResult without a Safety")
		}
		ids := []RuleID{}
		for _, u := range f.UncheckedRules {
			ids = append(ids, u.Rule)
		}
		out.Fix = &fixResultJSON{Safety: f.Safety, Written: nonNil(f.Written), Error: f.Error, UncheckedRules: ids}
	}
	return marshal(out)
}

type fixResultJSON struct {
	Safety         Safety            `json:"safety"`
	Written        []facts.InputPath `json:"written"`
	Error          string            `json:"error,omitempty"`
	UncheckedRules []RuleID          `json:"unchecked_rules"`
}

// marshal writes v without escaping <, > and &.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
