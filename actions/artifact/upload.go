package artifact

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	jobs "github.com/gh-intel/sisakulint/actions/job" // the test helper job takes the name
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// LeftCredential is a credential a step before an upload left in a file
// that an upload takes. Analyze gives each once, however many uploads take
// it (TakenCredential).
type LeftCredential struct {
	Step           *workflow.Step // the step that left it, of the steps of its job or action
	UsesText       string         // its uses, as written
	File           analysis.CredentialFile
	Lifetime       analysis.CredentialLifetime
	MissingCommits []prcode.MissingCommit // of the step's pin
	Checkout       bool                   // the step is actions/checkout
}

// TakenCredential is a LeftCredential an upload takes: its index in what
// Analyze gives, and whether the upload takes the file only as a hidden
// file, which the upload does on the condition of its HiddenMissingCommits.
type TakenCredential struct {
	Index  int
	Hidden bool
}

// Upload is a step of actions/upload-artifact and what it puts in its
// artifact.
type Upload struct {
	Step                  workflow.Step
	UsesText              string
	Path                  *workflow.String // nil when path is not a scalar
	DownloadableDuringRun bool             // others can download the artifact while the run goes on (v4 on)
	TokenWrite            analysis.TokenWrite
	TakenCredentials      []TakenCredential
	// HiddenMissingCommits are the commits that the pin of the upload's
	// release lacks when the release takes hidden files: the condition of
	// a TakenCredential whose Hidden is set (none when the release takes
	// them or not whatever its commits)
	HiddenMissingCommits []prcode.MissingCommit
	Inconclusive         []InconclusiveUpload
}

// Analyze is the uploads of the jobs of w, or of the composite steps of a,
// and the credentials they take, each once, in the order of their steps.
func Analyze(w *workflow.Workflow, a *workflow.ActionMetadata) ([]Upload, []LeftCredential) {
	var all []credential
	var out []Upload
	if w != nil {
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			out = append(out, uploads(&j, j.Steps.Value.Items, jobs.TokenWriteOf(j.Permissions, w.Permissions), &all)...)
		}
	}
	if a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
		out = append(out, uploads(nil, a.Runs.Value.Steps.Value.Items, analysis.TokenWriteYes, &all)...)
	}
	return out, taken(out, all)
}

// taken are the credentials of all that the uploads ups take, in the
// order of all; the indices of ups are made indices of them.
func taken(ups []Upload, all []credential) []LeftCredential {
	index := make([]int, len(all))
	for i := range index {
		index[i] = -1
	}
	for _, u := range ups {
		for _, t := range u.TakenCredentials {
			index[t.Index] = 0
		}
	}
	var out []LeftCredential
	for i, c := range all {
		if index[i] < 0 {
			continue
		}
		index[i] = len(out)
		out = append(out, LeftCredential{Step: c.step, UsesText: c.uses, File: fileOf(c.file), Lifetime: c.life, MissingCommits: c.unless, Checkout: c.checkout})
	}
	for _, u := range ups {
		for k := range u.TakenCredentials {
			u.TakenCredentials[k].Index = index[u.TakenCredentials[k].Index]
		}
	}
	return out
}

// uploads are the uploads of steps, each with the credentials the steps
// before it left, as indices of all, to which the credentials of steps are
// added. A gap of a credential is given with the first upload after its
// step, where it matters; a gap of an upload only when a step before it
// left a credential. j is the job of steps, nil for a composite action.
func uploads(j *workflow.Job, steps []workflow.Step, writes analysis.TokenWrite, all *[]credential) []Upload {
	order := workflow.OrderOf(steps)
	type leaver struct {
		at   int
		cs   []int // of all
		gaps []InconclusiveUpload
	}
	var leavers []leaver
	var ups []upload
	fileIDs := map[string]int{}
	for i := range steps {
		s := &steps[i]
		if u, ok := uploadOf(*s); ok {
			ups = append(ups, u)
			continue
		}
		place, placed := prcode.Placement{}, true
		if s.Uses.Status == workflow.Present && calls.IsCheckout(s.Uses.Value) {
			place, placed = prcode.CheckoutPlacement(j, steps, order, s.Order)
		}
		if cs, gaps := credentialsOf(s, place, placed); len(cs) > 0 || len(gaps) > 0 {
			l := leaver{at: s.Order, gaps: gaps}
			for _, c := range cs {
				k := strings.Join(c.file, "/")
				id, ok := fileIDs[k]
				if !ok {
					id = len(fileIDs)
					fileIDs[k] = id
				}
				c.fileID = id
				l.cs = append(l.cs, len(*all))
				*all = append(*all, c)
			}
			leavers = append(leavers, l)
		}
	}
	// a file a step leaves is there for the uploads that may run after it
	// starts, those of its parallel group and background ones among them;
	// what a step left is not known is told at the first of them
	told := make([]bool, len(leavers))
	var out []Upload
	var left []int // the credentials left before the upload, of all
	var m takeMemo
	for _, u := range ups {
		left = left[:0]
		var pending []InconclusiveUpload
		for i, l := range leavers {
			if !order.MayRunAfter(l.at, u.Step.Order) {
				continue
			}
			left = append(left, l.cs...)
			if !told[i] {
				pending, told[i] = append(pending, l.gaps...), true
			}
		}
		u.TokenWrite = writes
		u.Inconclusive = pending
		m.reset(len(u.exprs)+1, len(fileIDs))
		for _, g := range u.gaps {
			// a credential left before that the value decides the taking of;
			// with none, nothing the upload takes matters; of
			// include-hidden-files: those the lines of path take with
			// hidden files
			keep := func(c *credential) bool { return !g.hidden || !u.known || m.takes(u.glob, 0, c, true) }
			if fs := filesOf(left, *all, g.hidden, keep); len(fs) > 0 {
				g.gap.Files = fs
				g.gap.Credentials = gapCredentials(left, *all, g.hidden, keep)
				u.Inconclusive = append(u.Inconclusive, g.gap)
			}
		}
		u.expose(left, *all, &m)
		out = append(out, u.Upload)
	}
	return out
}

// takeMemo is what the lines of an upload take, by line (0 for the lines
// of path, 1 + i for the line i of exprs), credential file (fileID) and
// hidden: an upload asks it once for each file however many steps left
// one. One is made again for each upload (reset), on the same memory.
type takeMemo struct {
	v     []uint8 // 0 not asked, 1 not taken, 2 taken
	files int
}

// reset makes m empty for an upload of lines lines, among files files.
func (m *takeMemo) reset(lines, files int) {
	n := lines * files * 2
	if cap(m.v) < n {
		m.v = make([]uint8, n)
	} else {
		m.v = m.v[:n]
		clear(m.v)
	}
	m.files = files
}

// takes is g.takes of the file of c, g being the line line of the upload,
// asked once of m.
func (m *takeMemo) takes(g globLines, line int, c *credential, hidden bool) bool {
	i := (line*m.files + c.fileID) * 2
	if hidden {
		i++
	}
	switch m.v[i] {
	case 1:
		return false
	case 2:
		return true
	}
	v := g.takes(c.file, hidden)
	m.v[i] = 1
	if v {
		m.v[i] = 2
	}
	return v
}

// upload is what uploadOf reads of a step, for expose.
type upload struct {
	Upload
	lines  []string
	glob   globLines // lines, read once
	hidden hiddenRule
	input  bool // include-hidden-files is true
	pin    *prcode.MissingCommit
	known  bool // with and path were read
	// exprs are the lines of path with a ${{ }}, as a pattern that takes
	// at least what the line may (exprPattern), with the gap to give when
	// that pattern takes a credential left before
	exprs []exprLine
	// gaps are the other inputs not evaluated, given when a credential
	// left before is one the input decides the taking of
	gaps []inputGap
}

// inputGap is an input of the upload not evaluated; hidden is whether it
// decides the taking of hidden files only (include-hidden-files).
type inputGap struct {
	gap    InconclusiveUpload
	hidden bool
}

type exprLine struct {
	pattern string
	glob    globLines // pattern, read once
	gap     InconclusiveUpload
}

// exprPattern is the line l with each ${{ }} (prcode.ExprMark) made a glob that matches what
// it may be: ** for a whole part of the path, else * (a value with a slash
// in the middle of a part is not followed).
func exprPattern(l string) string {
	if t := strings.TrimLeft(l, " \t"); strings.HasPrefix(t, runnerTempRoot) {
		return runnerTempRoot + exprPattern(t[len(runnerTempRoot):]) // the mark is no ${{ }}
	}
	segs := strings.Split(l, "/")
	for i, seg := range segs {
		if strings.Trim(seg, prcode.ExprMark+" ") == "" && strings.Contains(seg, prcode.ExprMark) {
			segs[i] = "**"
		} else {
			segs[i] = strings.ReplaceAll(seg, prcode.ExprMark, "*")
		}
	}
	return strings.Join(segs, "/")
}

// uploadOf reads s as a step of actions/upload-artifact (the action
// itself, not one under it such as merge).
func uploadOf(s workflow.Step) (upload, bool) {
	act, ref := actionOf(s)
	if act != actionUpload {
		return upload{}, false
	}
	u := upload{Upload: Upload{Step: s, UsesText: s.Uses.Value.AsString()}}
	u.hidden, u.DownloadableDuringRun = uploadVersion(ref)
	if fullSHA.MatchString(ref) {
		u.pin = &prcode.MissingCommit{Repo: UploadRepo, SHA: mustSHA(ref)}
	}
	if s.With.Status == workflow.Dynamic {
		g := InconclusiveUpload{Kind: analysis.InconclusiveUploadInput, At: s.Base, Text: "with"}
		if s.With.Expr != nil {
			g.At, g.Text = s.With.Expr.Base, "with: "+s.With.Expr.Text()
		}
		u.gaps = append(u.gaps, inputGap{gap: g})
		return u, true
	}
	if v, present, dyn := valueOf(s, inputIncludeHiddenFiles); dyn {
		u.gaps = append(u.gaps, inputGap{gap: InconclusiveUpload{Kind: analysis.InconclusiveUploadInput, At: v.Base, Text: inputIncludeHiddenFiles.String() + ": " + v.Text()}, hidden: true})
	} else if present {
		u.input = isTrue(v)
	}
	v, present, dyn := valueOf(s, inputPath)
	if !present {
		return u, true
	}
	if e, _ := s.With.Value.Lookup(inputPath.String()); e.Value.Status == workflow.Present {
		p := e.Value.Value
		u.Path = &p
	}
	if dyn && v.Parts == nil {
		return u, true // the path is not a scalar: the model reports it
	}
	for _, pl := range prcode.PathLines(v) {
		l := pl.Text
		_, skip, ok, _ := parsePattern(l)
		g := InconclusiveUpload{Kind: analysis.InconclusiveUploadInput, At: v.Base, Text: inputPath.String() + ": " + strings.TrimSpace(pl.Raw)} // as written: the mark of RUNNER_TEMP is no text to show
		switch {
		case skip:
		case strings.Contains(l, prcode.ExprMark):
			if !strings.HasPrefix(strings.TrimSpace(l), "!") { // a line that leaves out: taking more is the worst case
				p := exprPattern(l)
				u.exprs = append(u.exprs, exprLine{pattern: p, glob: parseLines([]string{p}), gap: g})
			}
			continue
		case !ok || strings.Contains(l, "\\"):
			u.gaps = append(u.gaps, inputGap{gap: g})
			continue
		}
		u.lines = append(u.lines, l)
	}
	u.known = true
	u.glob = parseLines(u.lines)
	return u, true
}

// expose fills u.TakenCredentials with the credentials of left (of all)
// that u takes: with hidden files left out; else with them when the
// release takes them, on the condition of the release's commit
// (HiddenMissingCommits) when it is not known. m is what u's lines take.
func (u *upload) expose(left []int, all []credential, m *takeMemo) {
	if !u.known {
		return
	}
	for i, e := range u.exprs {
		// a value may name a hidden file itself
		keep := func(c *credential) bool { return m.takes(e.glob, i+1, c, true) }
		if fs := filesOf(left, all, false, keep); len(fs) > 0 {
			e.gap.Files = fs
			e.gap.Credentials = gapCredentials(left, all, false, keep)
			u.Inconclusive = append(u.Inconclusive, e.gap)
		}
	}
	if u.hidden == hiddenUnless && !u.input {
		for _, x := range uploadExcludes {
			u.HiddenMissingCommits = append(u.HiddenMissingCommits, prcode.MissingCommit{Repo: UploadRepo, SHA: u.pin.SHA, Commit: x})
		}
	}
	for _, ci := range left {
		c := &all[ci]
		hidden := true
		switch {
		case m.takes(u.glob, 0, c, false):
			hidden = false
		case !m.takes(u.glob, 0, c, true):
			continue
		case u.hidden == hiddenAlways || u.hidden == hiddenInput && u.input:
		case u.hidden == hiddenUnless:
		default:
			continue
		}
		if c.gap != nil { // whether the step leaves it is a ${{ }}: told at the first upload that takes it
			if !c.gapTold {
				u.Inconclusive, c.gapTold = append(u.Inconclusive, *c.gap), true
			}
			continue
		}
		u.TakenCredentials = append(u.TakenCredentials, TakenCredential{Index: ci, Hidden: hidden})
	}
}

// filesOf are the kinds of the files of the credentials cs (of all) that
// keep keeps, in order, once each; of hidden files only (a part of the
// path that starts with a dot) when hidden.
func filesOf(cs []int, all []credential, hidden bool, keep func(*credential) bool) []analysis.CredentialFile {
	var out []analysis.CredentialFile
	for _, ci := range cs {
		c := &all[ci]
		if hidden && !slices.ContainsFunc(c.file, func(p string) bool { return strings.HasPrefix(p, ".") && p != ".." }) {
			continue
		}
		if f := fileOf(c.file); !slices.Contains(out, f) && keep(c) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// gapCredentials are the steps and files of the credentials of cs (of
// all) whose files filesOf gives, in their order, each step and file
// once: those whose leaving a ${{ }} of the step decides (a gap of its
// own) are left out, as whether the step leaves the credential is not
// known.
func gapCredentials(cs []int, all []credential, hidden bool, keep func(*credential) bool) []GapCredential {
	var out []GapCredential
	for _, ci := range cs {
		c := &all[ci]
		if c.gap != nil || hidden && !slices.ContainsFunc(c.file, func(p string) bool { return strings.HasPrefix(p, ".") && p != ".." }) {
			continue
		}
		g := GapCredential{Step: c.step, File: fileOf(c.file)}
		if keep(c) && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}
