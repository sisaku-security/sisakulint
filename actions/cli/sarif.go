package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// SARIF 2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
// as GitHub code scanning reads it
// (https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
// Only what sarifLog writes is here.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	// sarifFingerprint is the key of partialFingerprints whose value is the
	// Fingerprint of a finding, whatever its certainty.
	// primaryLocationLineHash, the one key code scanning reads, has the
	// same value.
	sarifFingerprint = "sisakulintFingerprint/v1"
	sarifLineHash    = "primaryLocationLineHash"
	// sarifSrcRoot is the uriBaseId of each file of the repository: the
	// URI of the file is relative to the root of the repository.
	sarifSrcRoot = "%SRCROOT%"
	// sarifSrcRootText describes sarifSrcRoot in originalUriBaseIds, which
	// leaves out the URI of the root (SARIF 3.14.14), so that the SARIF
	// has no path of the machine of the run.
	sarifSrcRootText = "the root of the repository that the run read: the directory that --root names. The URI of each file in the SARIF is relative to the root of the repository."
	// sarifTextLimit is the most characters code scanning takes in the
	// short and the full description of a rule.
	sarifTextLimit = 1024
)

// sarifLevel is the level of a result, of the default of a rule, or of a
// notification (SARIF 3.27.10, 3.58.6). The zero sarifLevel is not one.
type sarifLevel uint8

const (
	levelUnset sarifLevel = iota
	levelNone
	levelNote
	levelWarning
	levelError
)

var sarifLevelNames = [...]string{"", "none", "note", "warning", "error"}

func (l sarifLevel) MarshalText() ([]byte, error) {
	if l == levelUnset || int(l) >= len(sarifLevelNames) {
		return nil, fmt.Errorf("sarifLevel(%d) is not a level", uint8(l))
	}
	return []byte(sarifLevelNames[l]), nil
}

// sarifKind is the kind of a result (SARIF 3.27.9). The zero sarifKind is
// fail, which a result leaves out: it is the default.
type sarifKind uint8

const (
	kindFail sarifKind = iota
	kindOpen           // the rule could not decide whether a problem exists
)

func (k sarifKind) MarshalText() ([]byte, error) {
	switch k {
	case kindFail:
		return []byte("fail"), nil
	case kindOpen:
		return []byte("open"), nil
	}
	return nil, fmt.Errorf("sarifKind(%d) is not a kind", uint8(k))
}

// sarifNewlines are the line breaks of the inputs, as YAML has them (CR
// LF, CR and LF), the longest first. SARIF counts lines by CR LF and LF
// when a run does not say (3.14.26), and so would put a region of a file
// with CR line breaks on another line.
var sarifNewlines = []string{"\r\n", "\r", "\n"}

type sarifFile struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool                `json:"tool"`
	Invocations []sarifInvocation        `json:"invocations"`
	BaseIDs     map[string]sarifBaseRoot `json:"originalUriBaseIds"`
	ColumnKind  string                   `json:"columnKind"`
	Newlines    []string                 `json:"newlineSequences"`
	Results     []sarifResult            `json:"results"`
}

// sarifBaseRoot is a URI base id of originalUriBaseIds without its URI.
type sarifBaseRoot struct {
	Description sarifMessage `json:"description"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Rules   []sarifDescriptor `json:"rules"`
}

type sarifDescriptor struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifMessage    `json:"shortDescription"`
	FullDescription      sarifMessage    `json:"fullDescription"`
	Help                 sarifHelp       `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRuleConfig struct {
	Level sarifLevel `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level     sarifLevel      `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Kind                sarifKind         `json:"kind,omitempty"`
	Level               sarifLevel        `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	CodeFlows           []sarifCodeFlow   `json:"codeFlows,omitempty"`
	RelatedLocations    []sarifLocation   `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Fixes               []sarifFix        `json:"fixes,omitempty"`
	Properties          any               `json:"properties,omitempty"` // *sarifResultProps of a finding, *sarifInconclusiveProps of an inconclusive finding
}

type sarifResultProps struct {
	Certainty      lint.Certainty       `json:"certainty"`
	Args           lint.FindingArgs     `json:"args"`
	AddedAttackers []lint.AddedAttacker `json:"added_attackers,omitempty"` // a run that adds no attacker does not report it (lint.RunAdded)
}

// sarifInconclusiveProps are the properties of the result of a finding
// whose certainty is inconclusive, which has no args but its kind.
type sarifInconclusiveProps struct {
	Certainty      lint.Certainty       `json:"certainty"`
	AddedAttackers []lint.AddedAttacker `json:"added_attackers,omitempty"` // a run that adds no attacker does not report it (lint.RunAdded)
}

type sarifLocation struct {
	ID               *int                  `json:"id,omitempty"`
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifMessage         `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// sarifRegion is a region of text, its columns counted in UTF-16 code
// units (run.columnKind) from 1; the end is the column after the last
// character.
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

type sarifFix struct {
	Description     sarifMessage          `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges"`
	Properties      sarifFixProps         `json:"properties"`
}

type sarifFixProps struct {
	Safety lint.Safety `json:"safety"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifact      `json:"artifactLocation"`
	Replacements     []sarifReplacement `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion   `json:"deletedRegion"`
	InsertedContent *sarifContent `json:"insertedContent,omitempty"`
}

type sarifContent struct {
	Text string `json:"text"`
}

// sarifLog is rep as a SARIF log of one run: a rule (a reportingDescriptor)
// for each finding kind of the rules and the quality rules that ran and for
// each inconclusive kind of the rules, and a result for each finding,
// quality finding and inconclusive place that no acceptance matched, of
// the inputs rep reports (Report.Narrow). The inputs not read and the
// internal errors are notifications of the invocation. version is the
// version of the binary; empty leaves it out.
func sarifLog(rep lint.Report, in lint.Inputs, reg *lint.Registry, version string) ([]byte, error) {
	rep = rep.Narrow()
	b := sarifBuilder{in: in, index: map[string]int{}, known: knownFacts(rep)}
	if err := b.rules(rep, reg); err != nil {
		return nil, err
	}
	var written []facts.InputPath // the inputs --fix wrote, whose fixes are made
	if rep.Fix != nil {
		written = rep.Fix.Written
	}
	results := []sarifResult{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		r, ok, err := b.finding(f.FindingDraft, f.Fingerprint, f.Certainty)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		r.Level = severityLevel(f.Severity)
		r.Properties.(*sarifResultProps).AddedAttackers = f.AddedAttackers
		if f.Certainty == lint.CertaintyConditional {
			r.Message.Text += " (" + b.conditionText(f) + ")"
		}
		if x, ok := b.fix(f, reg); ok && !slices.Contains(written, x.input) {
			r.Fixes = []sarifFix{x.fix}
		}
		results = append(results, r)
	}
	for _, f := range rep.QualityFindings {
		r, ok, err := b.finding(f.FindingDraft, f.Fingerprint, f.Certainty)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		r.Level = levelNote
		if f.Certainty == lint.CertaintyConditional {
			r.Message.Text += " (" + b.conditionText(lint.Finding{FindingDraft: f.FindingDraft}) + ")"
		}
		results = append(results, r)
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if g.Acceptance != nil {
			continue // code scanning keeps a result with suppressions open
		}
		r, ok, err := b.inconclusive(g)
		if err != nil {
			return nil, err
		}
		if ok {
			results = append(results, r)
		}
	}
	b.inputNotes(rep)
	if f := rep.Fix; f != nil {
		if len(f.Written) != 0 {
			names := make([]string, len(f.Written))
			for i, n := range f.Written {
				names[i] = n.String()
			}
			b.note(levelNote, "--fix wrote the fixes to "+strings.Join(names, ", ")+". The line and column numbers of the results are those of the files before --fix changed them. The SARIF has no fixes for the results in the files that --fix changed, because --fix already wrote those fixes to the files.")
		}
		if f.Error != "" {
			b.note(levelError, "--fix: "+f.Error)
		}
	}
	inv := sarifInvocation{ExecutionSuccessful: len(rep.Errors) == 0 && (rep.Fix == nil || rep.Fix.Error == ""), Notifications: b.notes}
	out := sarifFile{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{{
		Tool:        sarifTool{sarifDriver{Name: "sisakulint", Version: version, Rules: b.descriptors}},
		Invocations: []sarifInvocation{inv},
		BaseIDs:     map[string]sarifBaseRoot{sarifSrcRoot: {sarifMessage{sarifSrcRootText}}},
		ColumnKind:  "utf16CodeUnits",
		Newlines:    sarifNewlines,
		Results:     results,
	}}}
	return marshalSARIF(out)
}

type sarifBuilder struct {
	in          lint.Inputs
	descriptors []sarifDescriptor
	index       map[string]int // of descriptors, by ID
	known       map[string]facts.RawAnswer
	notes       []sarifNotification
}

// note adds a notification without a location.
func (b *sarifBuilder) note(l sarifLevel, text string) {
	b.notes = append(b.notes, sarifNotification{Level: l, Message: sarifMessage{text}})
}

// rules makes the descriptors: of each rule that ran, its finding kinds
// and then its inconclusive kinds; then of each quality rule that ran,
// its finding kinds.
func (b *sarifBuilder) rules(rep lint.Report, reg *lint.Registry) error {
	for _, x := range rep.Rules {
		m, ok := reg.Meta(x.ID)
		if !ok {
			return fmt.Errorf("the rule %s is not in the registry", x.ID)
		}
		help, err := reg.ExplainRule(x.ID)
		if err != nil {
			return err
		}
		tags := []string{"security"}
		for _, w := range m.Facets.Weakness {
			tags = append(tags, w.String())
		}
		if !slices.Contains(tags, m.ID.String()) { // a weakness may have the name of the rule
			tags = append(tags, m.ID.String())
		}
		for _, k := range m.FindingKinds {
			s := k.Severity()
			b.add(sarifDescriptor{
				ID: k.ID.String(), ShortDescription: sarifText(k.Consequence),
				FullDescription:      sarifText("problem: " + m.Problem + "\nconsequence: " + k.Consequence),
				Help:                 sarifHelp{Text: "remedy: " + k.Remedy + "\nexpected: " + m.Expected, Markdown: string(help)},
				DefaultConfiguration: sarifRuleConfig{severityLevel(s)},
				Properties:           sarifRuleProps{Tags: tags, SecuritySeverity: securitySeverity(s)},
			})
		}
		for _, k := range m.InconclusiveKinds {
			b.add(sarifDescriptor{
				ID: inconclusiveRuleID(m.ID, k.ID), ShortDescription: sarifText(k.Text),
				FullDescription: sarifText("the problem that the rule " + m.ID.String() + " looks for: " + m.Problem + "\nthe kind of place where the rule reaches no conclusion: " + k.Text),
				// no Markdown: the section of the rule is tens of kilobytes,
				// and a rule has more inconclusive kinds than finding kinds
				Help: sarifHelp{Text: lint.InconclusiveRemedy(m.ID) + ", and leaves the place out of the SARIF.\nthe kind of place: " + k.Text + "\nexpected: " + m.Expected},
				// the level and the security severity of the rule, as a
				// finding of the rule has, so that code scanning shows the
				// place among the security results of its severity
				DefaultConfiguration: sarifRuleConfig{severityLevel(m.Severity())},
				Properties:           sarifRuleProps{Tags: append([]string{"security", "inconclusive"}, tags[1:]...), SecuritySeverity: securitySeverity(m.Severity())},
			})
		}
	}
	for _, id := range rep.QualityRules {
		m, ok := reg.QualityMeta(id)
		if !ok {
			return fmt.Errorf("the quality rule %s is not in the registry", id)
		}
		help, err := reg.ExplainRule(id)
		if err != nil {
			return err
		}
		for _, k := range m.FindingKinds {
			b.add(sarifDescriptor{
				ID: k.ID.String(), ShortDescription: sarifText(k.Consequence),
				FullDescription:      sarifText("problem: " + m.Problem + "\nconsequence: " + k.Consequence),
				Help:                 sarifHelp{Text: "remedy: " + k.Remedy + "\nexpected: " + m.Expected, Markdown: string(help)},
				DefaultConfiguration: sarifRuleConfig{levelNote},
				Properties:           sarifRuleProps{Tags: []string{"quality", m.ID.String()}},
			})
		}
	}
	return nil
}

func (b *sarifBuilder) add(d sarifDescriptor) {
	d.Name = d.ID
	b.index[d.ID] = len(b.descriptors)
	b.descriptors = append(b.descriptors, d)
}

// inconclusiveRuleID is the ID of the descriptor of the inconclusive kind
// k of the rule id: <rule>.<kind>, as args.kind_id (lint.InconclusiveKindText),
// which the registry keeps apart from the ID of each finding kind.
func inconclusiveRuleID(id lint.RuleID, k lint.InconclusiveKindID) string {
	return lint.InconclusiveKindText(id, k)
}

// finding is the result of the finding or quality finding d, without its
// level and its fix. It is false, with a notification, for a finding in
// the file of a fact, which has no path in the repository.
func (b *sarifBuilder) finding(d lint.FindingDraft, fp lint.Fingerprint, c lint.Certainty) (sarifResult, bool, error) {
	id := d.Args.KindID().String()
	i, ok := b.index[id]
	if !ok {
		return sarifResult{}, false, fmt.Errorf("the kind %s of a finding is not of a rule that ran", id)
	}
	loc, err := b.location(d.Location)
	if err != nil {
		b.note(levelWarning, "a finding of "+id+" is left out of the SARIF: "+err.Error())
		return sarifResult{}, false, nil
	}
	r := sarifResult{
		RuleID: id, RuleIndex: i, Message: sarifMessage{d.Detected()}, Locations: []sarifLocation{loc},
		PartialFingerprints: map[string]string{sarifLineHash: fp.String(), sarifFingerprint: fp.String()},
		Properties:          &sarifResultProps{Certainty: c, Args: d.Args},
	}
	var steps []sarifThreadFlowLocation
	for _, e := range d.Evidence {
		if l, ok := b.related(e, nil); ok {
			steps = append(steps, sarifThreadFlowLocation{l})
		}
	}
	if len(steps) != 0 {
		r.CodeFlows = []sarifCodeFlow{{[]sarifThreadFlow{{steps}}}}
	}
	for _, x := range d.Related {
		n := len(r.RelatedLocations)
		if l, ok := b.related(x, &n); ok {
			r.RelatedLocations = append(r.RelatedLocations, l)
		}
	}
	r.Message.Text += relatedLinks(r.RelatedLocations) + factPlaces(d.Evidence, d.Related)
	return r, true, nil
}

// factPlaces names the places of rs in the files of facts, which a SARIF
// location cannot have (location): the fact as queryText writes it and the
// line, after the text of a message; empty when there is none.
func factPlaces(rs ...[]lint.Related) string {
	var places []string
	for _, xs := range rs {
		for _, x := range xs {
			if q := x.Location.File.Query; q != nil {
				places = append(places, linkEscape.Replace(queryText(q))+" line "+strconv.Itoa(x.Location.Position().Line))
			}
		}
	}
	if len(places) == 0 {
		return ""
	}
	return " (places in files of other repositories: " + strings.Join(places, ", ") + ")"
}

// linkEscape escapes the text of a message that a link or its text could
// take for the delimiters of a link (SARIF 2.1.0 3.11.6).
var linkEscape = strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`)

// relatedLinks are links to the related locations ls in a message (SARIF
// 2.1.0 3.11.6, embedded links), after the text of the message: each with
// the path and the line of the location as its text; empty for none.
// Code scanning links to a related location only from such a link.
func relatedLinks(ls []sarifLocation) string {
	if len(ls) == 0 {
		return ""
	}
	links := make([]string, len(ls))
	for i, l := range ls {
		at := l.PhysicalLocation.ArtifactLocation.URI
		if g := l.PhysicalLocation.Region; g != nil {
			at += ":" + strconv.Itoa(g.StartLine)
		}
		links[i] = "[" + linkEscape.Replace(at) + "](" + strconv.Itoa(*l.ID) + ")"
	}
	return " (related places: " + strings.Join(links, ", ") + ")"
}

// related is the location of x with its note; false for a place in the
// file of a fact, which has no path in the repository.
func (b *sarifBuilder) related(x lint.Related, id *int) (sarifLocation, bool) {
	l, err := b.location(x.Location)
	if err != nil {
		return sarifLocation{}, false
	}
	l.ID = id
	if x.Note != "" {
		l.Message = &sarifMessage{x.Note}
	}
	return l, true
}

// conditionText is what the condition of the conditional finding f
// rests on that the run does not know (decide): the facts, named as the
// text and --fact name them, and the inputs not read.
func (b *sarifBuilder) conditionText(f lint.Finding) string {
	lookup := func(n facts.InputPath) lint.LookupState { _, s := b.in.Lookup(n); return s }
	by, _ := decide([]lint.Finding{f}, b.known, lookup)
	d := by[0]
	var parts []string
	if n := len(d.facts); n > 0 {
		names := make([]string, n)
		for i, q := range d.facts {
			names[i] = queryText(q)
		}
		if n == 1 {
			parts = append(parts, "the run does not know the answer to the fact "+names[0]+", and the finding holds for some answers to the fact and not for others; --facts or --fact can give the answer")
		} else {
			parts = append(parts, "the run does not know the answers to the facts "+strings.Join(names, ", ")+", and the finding holds for some answers to the facts and not for others; --facts or --fact can give the answers")
		}
	}
	for _, n := range d.inputs {
		parts = append(parts, "the run did not read the input "+clean(n.String())+", and the finding holds for some contents of the input and not for others")
	}
	if len(parts) == 0 {
		return "conditional"
	}
	return "conditional: " + strings.Join(parts, "; ")
}

// inconclusiveMessage starts the message of the result of a finding whose
// certainty is inconclusive, which code scanning shows as an alert of the
// severity of its rule: it says that the rule decided nothing.
const inconclusiveMessage = "Inconclusive: the rule could not decide whether the place of the finding has the problem that the rule of the finding looks for. "

// inconclusive is the result of g, a finding whose certainty is
// inconclusive; false, with a notification, for a place in the file of a
// fact.
func (b *sarifBuilder) inconclusive(g lint.Finding) (sarifResult, bool, error) {
	id := inconclusiveRuleID(g.Rule, g.InconclusiveKind)
	i, ok := b.index[id]
	if !ok {
		return sarifResult{}, false, fmt.Errorf("the inconclusive kind %s is not of a rule that ran", id)
	}
	loc, err := b.location(g.Location)
	if err != nil {
		b.note(levelWarning, "an inconclusive finding of "+id+" is left out of the SARIF: "+err.Error())
		return sarifResult{}, false, nil
	}
	// the level of its rule, as a finding of the rule has: a kind other
	// than fail takes no level but none (SARIF 2.1.0 3.27.9), and code
	// scanning reads the level, not the kind
	r := sarifResult{
		RuleID: id, RuleIndex: i, Level: severityLevel(g.Severity), Message: sarifMessage{inconclusiveMessage + g.Detected()}, Locations: []sarifLocation{loc},
		PartialFingerprints: map[string]string{sarifLineHash: g.Fingerprint.String(), sarifFingerprint: g.Fingerprint.String()},
		Properties:          &sarifInconclusiveProps{Certainty: g.Certainty, AddedAttackers: g.AddedAttackers},
	}
	for _, x := range g.Related {
		n := len(r.RelatedLocations)
		if l, ok := b.related(x, &n); ok {
			r.RelatedLocations = append(r.RelatedLocations, l)
		}
	}
	r.Message.Text += relatedLinks(r.RelatedLocations) + factPlaces(g.Related)
	return r, true, nil
}

// inputFix is a fix and the input it edits.
type inputFix struct {
	fix   sarifFix
	input facts.InputPath
}

// fix is the fix of f: its edits as replacements of the regions of the
// input they are in, before the edits, in the order edit.Apply makes them
// (by where they start, an insertion before a replacement at the same
// place), which is the order SARIF applies them in (3.57.1); an edit that
// changes nothing is left out, as edit.Apply leaves it. It is false when
// f has no fix, or a fix that changes nothing.
func (b *sarifBuilder) fix(f lint.Finding, reg *lint.Registry) (inputFix, bool) {
	x, ok := f.FixInput(b.in)
	if !ok {
		return inputFix{}, false
	}
	m, _ := reg.Meta(f.Rule)
	k, _ := m.FixKind(f.Fix.KindID)
	src := x.Tree.Bytes()
	var edits []edit.Edit
	for _, e := range f.Fix.Edits {
		if !bytes.Equal(src[e.Span.Start:e.Span.End], e.New) {
			edits = append(edits, e)
		}
	}
	if len(edits) == 0 {
		return inputFix{}, false
	}
	slices.SortStableFunc(edits, func(a, b edit.Edit) int {
		return cmp.Or(cmp.Compare(a.Span.Start, b.Span.Start), cmp.Compare(a.Span.End, b.Span.End))
	})
	change := sarifArtifactChange{ArtifactLocation: sarifArtifactOf(x.Name)}
	for _, e := range edits {
		r := sarifReplacement{DeletedRegion: regionOf(x.Tree, e.Span)}
		if len(e.New) != 0 {
			r.InsertedContent = &sarifContent{string(e.New)}
		}
		change.Replacements = append(change.Replacements, r)
	}
	return inputFix{sarifFix{Description: sarifMessage{f.Fix.Title}, ArtifactChanges: []sarifArtifactChange{change}, Properties: sarifFixProps{k.Safety}}, x.Name}, true
}

// location is where l is; an error for a place in the file of a fact.
func (b *sarifBuilder) location(l lint.Location) (sarifLocation, error) {
	if l.File.Query != nil {
		return sarifLocation{}, errors.New("the place is in an action.yml of another repository, which the run fetched as the answer to a fact, not in a file of this repository, and code scanning shows only places in files of this repository")
	}
	x, _ := b.in.Lookup(l.File.Input)
	if x.Tree == nil {
		return sarifLocation{}, fmt.Errorf("a place in %s, which was not read", l.File.Input)
	}
	r := regionOf(x.Tree, l.Span)
	return sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactOf(l.File.Input), Region: &r}}, nil
}

// inputNotes adds the notifications of the inputs of rep not read, of each
// diagnostic of an input not valid, and of the internal errors.
func (b *sarifBuilder) inputNotes(rep lint.Report) {
	out := b.notes
	for _, i := range rep.ReportedInputs() {
		if i.State == lint.InputStateRead || i.State == lint.InputStateExcluded {
			continue
		}
		at := []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactOf(i.Name)}}}
		if i.Reason != "" || len(i.Diagnostics) == 0 || i.Tree == nil {
			text := i.Name.String() + ": " + i.State.String()
			if i.Reason != "" {
				text += ": " + i.Reason
			}
			out = append(out, sarifNotification{Level: levelError, Message: sarifMessage{text}, Locations: at})
			continue
		}
		for _, d := range i.Diagnostics {
			r := regionOf(i.Tree, d.Span)
			l := at[0]
			l.PhysicalLocation.Region = &r
			out = append(out, sarifNotification{Level: levelError, Message: sarifMessage{i.Name.String() + ": " + i.State.String() + ": " + d.Code.String() + ": " + d.Msg}, Locations: []sarifLocation{l}})
		}
	}
	for _, e := range rep.Errors {
		var parts []string
		if !e.Rule.IsZero() {
			parts = append(parts, e.Rule.String())
		}
		if !e.Input.IsZero() {
			parts = append(parts, e.Input.String())
		}
		out = append(out, sarifNotification{Level: levelError, Message: sarifMessage{strings.Join(append(parts, e.Message), ": ")}})
	}
	b.notes = out
}

// regionOf is the span sp of t, its columns in UTF-16 code units: a byte
// that is not UTF-8 counts as one, as U+FFFD would. A byte order mark is
// not counted (SARIF 3.30.2). The end of a file that ends in a line break
// is on the last line, after the line break, not on a line after it.
func regionOf(t *cst.Tree, sp cst.Span) sarifRegion {
	src := t.Bytes()
	col := func(off int) (line, column int) {
		line = t.Position(off).Line
		start := t.LineStart(line)
		if off == len(src) && off > 0 && start == off && line > 1 {
			line--
			start = t.LineStart(line)
		}
		s := src[start:off]
		if line == 1 {
			s = bytes.TrimPrefix(s, []byte("\xef\xbb\xbf"))
		}
		n := 0
		for len(s) > 0 {
			r, w := utf8.DecodeRune(s)
			if r >= 0x10000 {
				n += 2
			} else {
				n++
			}
			s = s[w:]
		}
		return line, n + 1
	}
	sl, sc := col(sp.Start)
	el, ec := col(sp.End)
	return sarifRegion{sl, sc, el, ec}
}

// sarifArtifactOf is the path p of the repository as a relative reference
// of RFC 3986 from sarifSrcRoot. Code scanning reads the reference from the
// root of the repository.
func sarifArtifactOf(p facts.InputPath) sarifArtifact {
	return sarifArtifact{(&url.URL{Path: p.String()}).String(), sarifSrcRoot}
}

// sarifText is s as code scanning takes it in a description: at most
// sarifTextLimit characters, the last of them … when s is cut.
func sarifText(s string) sarifMessage {
	if utf8.RuneCountInString(s) <= sarifTextLimit {
		return sarifMessage{s}
	}
	return sarifMessage{string([]rune(s)[:sarifTextLimit-1]) + "…"}
}

// severityLevel is the level of a result of the severity s: error for a
// serious problem, warning for a problem, note for a minor one (SARIF
// 3.27.10).
func severityLevel(s lint.Severity) sarifLevel {
	switch s {
	case lint.SeverityCritical, lint.SeverityHigh:
		return levelError
	case lint.SeverityMedium:
		return levelWarning
	}
	return levelNote
}

// securitySeverity is a score in the band of code scanning that has the
// name of s (over 9.0 critical, 7.0 to 8.9 high, 4.0 to 6.9 medium, 0.1 to
// 3.9 low): not a CVSS score. Info is in the band of low, below low.
func securitySeverity(s lint.Severity) string {
	return map[lint.Severity]string{lint.SeverityCritical: "9.5", lint.SeverityHigh: "8.0", lint.SeverityMedium: "5.5", lint.SeverityLow: "2.0", lint.SeverityInfo: "1.0"}[s]
}

// marshalSARIF writes v, indented, without escaping <, > and &, with a
// line break at the end.
func marshalSARIF(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
