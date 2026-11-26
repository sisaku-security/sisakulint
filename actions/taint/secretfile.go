package taint

import (
	"regexp"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// secretFileWrite is a variable a run writes to $GITHUB_ENV or
// $GITHUB_OUTPUT (NAME=value, or NAME<<DELIM and its lines), and the
// secrets its value carries: the
// steps after it get the variable in their env, or the output in
// steps.<id>.outputs.
type secretFileWrite struct {
	file    analysis.EnvironmentFile
	name    string
	secrets []CarriedSecret
	at      shell.Span // the command that writes it
	value   string     // literal: the value
	literal bool       // the value is written in the run, with no variable nor ${{ }}
}

// stepKey is a step of a job (the job's id, "" in an action.yml), by its
// order.
type stepKey struct {
	job   string
	order int
}

// crossMemo is, for each step, its secretFileWrites, read once. A step
// being read has a nil entry: a cycle of needs reads nothing.
type crossMemo map[stepKey][]secretFileWrite

// fileLine is a line of an environment file a write starts: NAME=value
// or NAME<<DELIM.
var (
	fileLine    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)=`)
	fileHeredoc = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)<<(.+)$`)
)

// writesOf are the secretFileWrites of the step i of c.before, read in the
// scope of that step.
func (c scope) writesOf(i int) []secretFileWrite {
	s := c.before[i]
	k := stepKey{c.jobID(), s.Order}
	if c.cross == nil {
		return nil
	}
	if w, ok := (*c.cross)[k]; ok {
		return w
	}
	(*c.cross)[k] = nil
	if s.Run.Status != workflow.Present {
		return nil
	}
	e := c
	e.before, e.memo = c.before[:i], map[envKey]ExprRef{}
	e.jobNarrowings, e.stepNarrowing = nil, attacker.Narrowing{} // c's narrowings are of the step that reads, not of the step i that writes
	e.envs = []workflow.Field[workflow.Map[workflow.String]]{s.Env}
	if c.job != nil {
		e.envs = append(e.envs, c.job.Env, c.wf.Env)
	}
	sink := Sink{Step: s, Job: c.job, Kind: analysis.SinkRun, Value: s.Run.Value, Envs: e.envs}
	sink.setShell(c.wf)
	if sink.Shell != ShellBash && sink.Shell != ShellSh {
		return nil
	}
	w := e.secretFlowOf(&sink).fileWrites()
	(*c.cross)[k] = w
	return w
}

func (c scope) jobID() string {
	if c.job == nil {
		return ""
	}
	return expr.FoldName(c.job.ID.AsString())
}

// fileNamedBy is the environment file the word w names: $GITHUB_ENV or
// $GITHUB_OUTPUT alone, in braces or quotes or not.
func fileNamedBy(text string, w shell.Word) analysis.EnvironmentFile {
	if len(w.Parts) != 1 {
		return analysis.EnvironmentFileUnset
	}
	p := w.Parts[0]
	if !wholeValue(p) {
		return analysis.EnvironmentFileUnset
	}
	if f := fileNamed(p.Name.String()); f == analysis.EnvironmentFileEnv || f == analysis.EnvironmentFileOutput {
		return f
	}
	return analysis.EnvironmentFileUnset
}

// fileWrites are what the run writes to $GITHUB_ENV and $GITHUB_OUTPUT.
func (f *secretFlow) fileWrites() []secretFileWrite {
	var spans []shell.Span
	for _, h := range f.holes {
		spans = append(spans, h.span)
	}
	writes := shell.Writes(f.text, f.script, shell.WriteOptions{
		Target:      func(w shell.Word) bool { return fileNamedBy(f.text, w) != analysis.EnvironmentFileUnset },
		Holes:       spans,
		EchoEscapes: f.s.Shell == ShellSh,
		NotRead:     &f.s.CallsNotRead,
		Visibility:  f.vis,
	})
	var out []secretFileWrite
	for _, w := range writes {
		file := fileNamedBy(f.text, w.Target)
		if file == analysis.EnvironmentFileUnset || w.Exec {
			continue
		}
		r := lineSplitter{f: f, file: file, at: w.At.Span()}
		for _, o := range w.Out {
			r.piece(o)
		}
		r.end()
		out = append(out, r.out...)
	}
	return out
}

// lineSplitter reads the pieces of a write into its lines.
type lineSplitter struct {
	f       *secretFlow
	file    analysis.EnvironmentFile
	at      shell.Span
	head    strings.Builder // the literal text of the line before what is not literal
	headEnd bool
	secrets []CarriedSecret
	// heredoc is the name and the delimiter of a NAME<<DELIM being read,
	// and kept the secrets of its lines.
	heredoc, delim string
	kept           []CarriedSecret
	out            []secretFileWrite
}

func (r *lineSplitter) piece(o shell.Out) {
	switch o.Kind {
	case shell.OutLit:
		lines := strings.Split(o.Text, "\n")
		for i, l := range lines {
			if !r.headEnd {
				r.head.WriteString(l)
			}
			if i < len(lines)-1 {
				r.endLine()
			}
		}
		return
	case shell.OutParam:
		cs := r.f.secretsInParts([]shell.Part{*o.Part}, o.Span.Start, o.Span.Start, 0)
		if e := expansionOf(*o.Part); !e.opaque && e.change == analysis.ExpansionChangeUnset && r.f.maskedInStep(o.Part.Name.String(), o.Span.Start) {
			for i := range cs {
				cs[i].Masked = true // the step registers the value before the steps after it start
			}
		}
		r.secrets = append(r.secrets, cs...)
	case shell.OutHole:
		h := r.f.holes[o.Hole]
		r.secrets = append(r.secrets, r.f.exprSecrets(r.f.s.Value.Parts[h.part].Tree, expr.Span{Start: h.span.Start, End: h.span.End}, shell.VarName{}, 0)...)
	case shell.OutSubst:
		if o.Part.Sub != nil {
			r.secrets = append(r.secrets, r.f.substitutionSecrets(*o.Part, o.Span.Start, 0, nil)...)
		}
	case shell.OutUnknown:
		r.secrets = append(r.secrets, r.f.writerSecrets(o)...)
	}
	r.headEnd = true
}

// endLine ends the line read: a NAME=value, a NAME<<DELIM, a line of the
// heredoc, or its delimiter.
func (r *lineSplitter) endLine() {
	head, secrets, mixed := r.head.String(), r.secrets, r.headEnd
	r.head.Reset()
	r.headEnd, r.secrets = false, nil
	switch {
	case r.heredoc != "" && head == r.delim && len(secrets) == 0:
		r.emit(r.heredoc, r.kept)
		r.heredoc, r.kept = "", nil
	case r.heredoc != "":
		r.kept = append(r.kept, secrets...)
	case len(secrets) == 0 && fileHeredoc.MatchString(head):
		m := fileHeredoc.FindStringSubmatch(head)
		r.heredoc, r.delim = m[1], m[2]
	default:
		if m := fileLine.FindStringSubmatch(head); m != nil {
			r.emit(m[1], secrets)
			if !mixed {
				r.out[len(r.out)-1].value, r.out[len(r.out)-1].literal = strings.TrimPrefix(head, m[0]), true
			}
		}
	}
}

func (r *lineSplitter) end() {
	if r.head.Len() > 0 || len(r.secrets) > 0 {
		r.endLine()
	}
}

func (r *lineSplitter) emit(name string, secrets []CarriedSecret) {
	r.out = append(r.out, secretFileWrite{file: r.file, name: name, secrets: uniqueSecrets(secrets), at: r.at})
}

// crossEnv is the secrets of the variable name a step before the step of
// f writes to $GITHUB_ENV, the last one that is done before it: false when
// none writes it.
func (f *secretFlow) crossEnv(name string) ([]CarriedSecret, bool) {
	c := f.c
	for i := len(c.before) - 1; i >= 0; i-- {
		if !c.order.DoneBefore(c.before[i].Order, len(c.before)) {
			continue
		}
		ws := c.writesOf(i)
		for j := len(ws) - 1; j >= 0; j-- {
			if ws[j].file == analysis.EnvironmentFileEnv && ws[j].name == name {
				return ws[j].secrets, true
			}
		}
	}
	return nil, false
}

// outputSecretsOf are the secrets the output name (all of them for "") of
// the step id of the steps before carries: what the last step done before
// with the id writes to $GITHUB_OUTPUT.
func (c scope) outputSecretsOf(id, name string) []CarriedSecret {
	for i := len(c.before) - 1; i >= 0; i-- {
		s := c.before[i]
		if !c.order.DoneBefore(s.Order, len(c.before)) || s.ID.Status != workflow.Present || expr.FoldName(s.ID.Value.AsString()) != id {
			continue
		}
		var out []CarriedSecret
		for _, w := range c.writesOf(i) {
			if w.file == analysis.EnvironmentFileOutput && (name == "" || expr.FoldName(w.name) == name) {
				out = append(out, w.secrets...)
			}
		}
		return out
	}
	return nil
}

// jobOutputSecrets are the secrets the output name of the job id needed
// carries, through steps.<id>.outputs in the job's outputs. GitHub does not
// give an output with a value it masks, so an output that carries a secret
// as it is carries none.
func (c scope) jobOutputSecrets(id, name string, depth int) []CarriedSecret {
	if c.job == nil || c.job.Needs.Status != workflow.Present || depth > 16 {
		return nil
	}
	needed := slices.ContainsFunc(c.job.Needs.Value.Items, func(n workflow.String) bool { return expr.FoldName(n.AsString()) == id })
	j, ok := c.jobs[id]
	if !needed || !ok || j.Outputs.Status != workflow.Present {
		return nil
	}
	steps := j.Steps.Value.Items
	e := c
	e.job, e.before, e.order, e.memo = &j, steps, workflow.OrderOf(steps), map[envKey]ExprRef{}
	e.jobNarrowings, e.stepNarrowing = nil, attacker.Narrowing{} // the ifs of another job
	var out []CarriedSecret
	for _, ent := range j.Outputs.Value.Entries {
		if name != "" && expr.FoldName(ent.Key.AsString()) != name || ent.Value.Status != workflow.Present {
			continue
		}
		var cs []CarriedSecret
		for _, p := range ent.Value.Value.Parts {
			if !p.Expr || p.Tree == nil {
				continue
			}
			outputRefs(p.Tree, func(kind, oid, oname string) {
				if kind == "steps" {
					cs = append(cs, e.outputSecretsOf(oid, oname)...)
				}
			})
		}
		if !slices.ContainsFunc(cs, func(x CarriedSecret) bool { return x.Form == analysis.SecretFormVerbatim || x.Masked }) {
			out = append(out, cs...)
		}
	}
	return out
}

// outputRefs calls f with each steps.<id>.outputs.<name> and
// needs.<id>.outputs.<name> of n (name "" for all the outputs).
func outputRefs(n expr.Node, f func(kind, id, name string)) {
	if p, ok := expr.AccessPath(n); ok {
		if len(p) >= 3 && (expr.EqualName(p[0].Name, "steps") || expr.EqualName(p[0].Name, "needs")) && p[1].Name != "" && expr.EqualName(p[2].Name, "outputs") {
			name := ""
			if len(p) > 3 {
				name = expr.FoldName(p[3].Name)
			}
			f(expr.FoldName(p[0].Name), expr.FoldName(p[1].Name), name)
		}
		return
	}
	for _, c := range expr.Children(n) {
		outputRefs(c, f)
	}
}

// exprSecrets are the secrets the expression n carries, at span through
// v: those it reads (carriedOf), and those of the outputs of the steps
// before and of the jobs needed.
func (f *secretFlow) exprSecrets(n expr.Node, span expr.Span, v shell.VarName, depth int) []CarriedSecret {
	out := carriedOf(n, span, v)
	if n == nil {
		return out
	}
	for _, c := range f.c.outputCarried(n, depth) {
		c.Span, c.Var = span, v
		out = append(out, c)
	}
	return out
}

// outputCarried are the secrets the outputs n reads carry: of the steps
// before and of the jobs needed.
func (c scope) outputCarried(n expr.Node, depth int) []CarriedSecret {
	var out []CarriedSecret
	outputRefs(n, func(kind, id, name string) {
		if kind == "steps" {
			out = append(out, c.outputSecretsOf(id, name)...)
		} else {
			out = append(out, c.jobOutputSecrets(id, name, depth+1)...)
		}
	})
	return out
}
